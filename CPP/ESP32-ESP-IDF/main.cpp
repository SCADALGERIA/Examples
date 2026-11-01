/*
 * SCADALGERIA Direct Firmware example — C++ / ESP32 / ESP-IDF 6.1
 *
 * This is a single-file protocol example. It deliberately focuses on the
 * SCADALGERIA Direct Firmware protocol and local GPIO, not on Wi-Fi provisioning, OTA,
 * watchdogs, or a complete ESP-IDF project structure.
 *
 * Flow demonstrated here:
 *
 *   GPIO4 -> di.input1 -> encrypted MQTT telemetry
 *   SCADALGERIA platform -> encrypted do.output1 command -> GPIO18
 *   GPIO18 result -> encrypted CommandResultDto
 *
 * The surrounding firmware must establish networking and a valid UTC clock
 * before the MQTT client starts.
 */

// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mqtt_client.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_spiffs.h"
#include "cJSON.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

#include <msgpack.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <sys/time.h>
#include <vector>

using Bytes = std::vector<std::uint8_t>;


// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
// ============================================================================
//
// Put Connection → Copy firmware configuration → Copy JSON at
// `/spiffs/scadalgeria-connection.json`. Keep the API-key secret separately in
// NVS namespace `scada_secret`, key `api_key`.

namespace ScadaConfig {

constexpr const char *ConnectionConfigFile = "/spiffs/scadalgeria-connection.json";
constexpr const char *InputTag = "di.input1";
constexpr const char *OutputTag = "do.output1";
constexpr gpio_num_t InputPin = GPIO_NUM_4;
constexpr gpio_num_t OutputPin = GPIO_NUM_18;
constexpr std::uint32_t TelemetryIntervalMs = 1000;
constexpr std::size_t MaxIncomingPayloadBytes = 4096;

char mqttHost[256]{};
int mqttPort{};
char clientId[32]{};
char mqttUsername[384]{};
char keyId[64]{};
char apiToken[512]{};
char authChallengeTopic[512]{};
char authResponseTopic[512]{};
char telemetryTopic[512]{};
char commandsTopic[512]{};
char commandResultTopic[512]{};

static char *ReadTextFile(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file) return nullptr;
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    if (size <= 0) { fclose(file); return nullptr; }
    auto *text = static_cast<char *>(calloc(static_cast<std::size_t>(size) + 1, 1));
    if (!text) { fclose(file); return nullptr; }
    if (fread(text, 1, static_cast<std::size_t>(size), file) != static_cast<std::size_t>(size)) { free(text); fclose(file); return nullptr; }
    fclose(file);
    return text;
}

static cJSON *RequiredObject(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsObject(value)) abort();
    return value;
}

static const char *RequiredString(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsString(value) || value->valuestring == nullptr || *value->valuestring == '\0') abort();
    return value->valuestring;
}

static int RequiredInt(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsNumber(value)) abort();
    return value->valueint;
}

static void CopyString(char *destination, std::size_t capacity, const char *value)
{
    if (strlen(value) + 1 > capacity) abort();
    strlcpy(destination, value, capacity);
}

static void CreateUniqueClientId()
{
    std::uint8_t random[8];
    static constexpr char Hex[] = "0123456789abcdef";
    esp_fill_random(random, sizeof(random));
    memcpy(clientId, "scada-", 6);
    for (std::size_t i = 0; i < sizeof(random); ++i) {
        clientId[6 + i * 2] = Hex[(random[i] >> 4) & 0x0F];
        clientId[7 + i * 2] = Hex[random[i] & 0x0F];
    }
    clientId[22] = '\0';
}

static void ResolveClientTopic(const char *topicTemplate, char *destination, std::size_t capacity)
{
    const char *marker = strstr(topicTemplate, "{clientId}");
    if (!marker || strstr(marker + 10, "{clientId}")) abort();
    std::size_t prefix = static_cast<std::size_t>(marker - topicTemplate);
    int written = snprintf(destination, capacity, "%.*s%s%s", static_cast<int>(prefix), topicTemplate, clientId, marker + 10);
    if (written < 0 || static_cast<std::size_t>(written) >= capacity) abort();
}

static void RequireBooleanTag(cJSON *root, const char *address, const char *direction)
{
    cJSON *tags = cJSON_GetObjectItemCaseSensitive(root, "tags");
    if (!cJSON_IsArray(tags)) abort();
    int matches = 0;
    cJSON *tag = nullptr;
    cJSON_ArrayForEach(tag, tags) {
        if (strcmp(RequiredString(tag, "address"), address) == 0) {
            ++matches;
            if (strcmp(RequiredString(tag, "dataType"), "Boolean") != 0 || strcmp(RequiredString(tag, "direction"), direction) != 0) abort();
        }
    }
    if (matches != 1) abort();
}

static void LoadApiKeySecret()
{
    nvs_handle_t handle{};
    ESP_ERROR_CHECK(nvs_open("scada_secret", NVS_READONLY, &handle));
    std::size_t length = sizeof(apiToken);
    ESP_ERROR_CHECK(nvs_get_str(handle, "api_key", apiToken, &length));
    nvs_close(handle);
    if (length < 2 || length > sizeof(apiToken)) abort();
}

void LoadProvisioning()
{
    esp_vfs_spiffs_conf_t spiffs{ .base_path = "/spiffs", .partition_label = nullptr, .max_files = 4, .format_if_mount_failed = false };
    esp_err_t mountResult = esp_vfs_spiffs_register(&spiffs);
    if (mountResult != ESP_OK && mountResult != ESP_ERR_INVALID_STATE) ESP_ERROR_CHECK(mountResult);

    char *jsonText = ReadTextFile(ConnectionConfigFile);
    if (!jsonText) abort();
    cJSON *root = cJSON_Parse(jsonText);
    free(jsonText);
    if (!root) abort();

    if (strcmp(RequiredString(root, "schema"), "scadalgeria.direct-firmware.connection") != 0 || RequiredInt(root, "schemaVersion") != 1) abort();
    cJSON *connection = RequiredObject(root, "connection");
    cJSON *identity = RequiredObject(root, "identity");
    cJSON *mqtt = RequiredObject(root, "mqtt");
    cJSON *broker = RequiredObject(mqtt, "broker");
    cJSON *topics = RequiredObject(mqtt, "topics");
    cJSON *qos = RequiredObject(mqtt, "qos");
    cJSON *authentication = RequiredObject(root, "authentication");
    cJSON *encryption = RequiredObject(root, "encryption");
    cJSON *kdf = RequiredObject(encryption, "sessionKeyDerivation");
    cJSON *secrets = RequiredObject(root, "secrets");

    if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(connection, "enabled"))) abort();
    if (strcmp(RequiredString(mqtt, "protocol"), "3.1.1") != 0 || !cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(mqtt, "cleanSession"))) abort();
    if (strcmp(RequiredString(broker, "transport"), "tcp") != 0) abort();
    if (strcmp(RequiredString(mqtt, "clientIdRequirement"), "unique-per-active-session") != 0) abort();
    if (RequiredInt(qos, "telemetry") != 1 || RequiredInt(qos, "commands") != 1 || RequiredInt(qos, "commandResults") != 1) abort();
    if (strcmp(RequiredString(authentication, "scheme"), "HMAC-SHA256") != 0 || strcmp(RequiredString(encryption, "scheme"), "AES-256-GCM") != 0) abort();
    if (strcmp(RequiredString(kdf, "algorithm"), "HKDF-SHA256") != 0 || strcmp(RequiredString(kdf, "info"), "SCADA-ENC-v1") != 0) abort();
    if (!cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(secrets, "apiKeySecretIncluded"))) abort();

    RequireBooleanTag(root, InputTag, "Input");
    RequireBooleanTag(root, OutputTag, "Output");
    CreateUniqueClientId();
    CopyString(mqttHost, sizeof(mqttHost), RequiredString(broker, "host"));
    mqttPort = RequiredInt(broker, "port");
    CopyString(mqttUsername, sizeof(mqttUsername), RequiredString(mqtt, "username"));
    CopyString(keyId, sizeof(keyId), RequiredString(identity, "keyId"));
    ResolveClientTopic(RequiredString(topics, "authenticationChallenge"), authChallengeTopic, sizeof(authChallengeTopic));
    ResolveClientTopic(RequiredString(topics, "authenticationResponse"), authResponseTopic, sizeof(authResponseTopic));
    CopyString(telemetryTopic, sizeof(telemetryTopic), RequiredString(topics, "telemetry"));
    CopyString(commandsTopic, sizeof(commandsTopic), RequiredString(topics, "commands"));
    CopyString(commandResultTopic, sizeof(commandResultTopic), RequiredString(topics, "commandResults"));
    LoadApiKeySecret();
    cJSON_Delete(root);
}

} // namespace ScadaConfig

static const char *LogTag = "scada-cpp-example";


// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
// ============================================================================

class DigitalIo {
public:
    void Initialize()
    {
        gpio_config_t input{};
        input.pin_bit_mask = 1ULL << ScadaConfig::InputPin;
        input.mode = GPIO_MODE_INPUT;
        input.pull_up_en = GPIO_PULLUP_ENABLE;
        input.pull_down_en = GPIO_PULLDOWN_DISABLE;
        input.intr_type = GPIO_INTR_DISABLE;

        gpio_config_t output{};
        output.pin_bit_mask = 1ULL << ScadaConfig::OutputPin;
        output.mode = GPIO_MODE_OUTPUT;
        output.pull_up_en = GPIO_PULLUP_DISABLE;
        output.pull_down_en = GPIO_PULLDOWN_DISABLE;
        output.intr_type = GPIO_INTR_DISABLE;

        ESP_ERROR_CHECK(gpio_config(&input));
        ESP_ERROR_CHECK(gpio_config(&output));

        // Safe initial state for the example.
        ESP_ERROR_CHECK(gpio_set_level(ScadaConfig::OutputPin, 0));
    }

    int ReadInput() const
    {
        // GPIO4 uses a pull-up, so closing the contact to GND means logical 1.
        return gpio_get_level(ScadaConfig::InputPin) == 0 ? 1 : 0;
    }

    bool WriteOutput(int value) const
    {
        if (value != 0 && value != 1) {
            return false;
        }

        return gpio_set_level(ScadaConfig::OutputPin, value) == ESP_OK;
    }
};

static DigitalIo digitalIo;


// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
// ============================================================================
//
// The outgoing envelope sequence is protocol state, not connection state.
// Persist the next value before it is used so reboot/reconnect cannot replay
// a previous logical message number.
//
// Commands are at-least-once. We store the final *inner* CommandResultDto and
// encrypt it again with a fresh sequence/nonce if the same command Id returns.

constexpr std::size_t CommandCacheCapacity = 16;
constexpr std::size_t CommandResultMaxBytes = 512;
constexpr std::size_t CommandIdMaxBytes = 128;

struct CommandCacheEntry {
    char commandId[CommandIdMaxBytes + 1]{};
    std::uint16_t payloadLength{};
    std::array<std::uint8_t, CommandResultMaxBytes> payload{};
};

class DurableState {
public:
    void Initialize()
    {
        ESP_ERROR_CHECK(nvs_open("scada", NVS_READWRITE, &handle_));

        esp_err_t sequenceResult = nvs_get_u64(handle_, "seq", &sequence_);
        if (sequenceResult == ESP_ERR_NVS_NOT_FOUND) {
            sequence_ = 0;
        } else {
            ESP_ERROR_CHECK(sequenceResult);
        }

        std::size_t cacheBytes = sizeof(cache_);
        esp_err_t cacheResult =
            nvs_get_blob(handle_, "results", cache_.data(), &cacheBytes);

        if (cacheResult == ESP_OK) {
            count_ = cacheBytes / sizeof(CommandCacheEntry);
            if (count_ > cache_.size()) {
                abort();
            }
        } else if (cacheResult == ESP_ERR_NVS_NOT_FOUND) {
            count_ = 0;
        } else {
            ESP_ERROR_CHECK(cacheResult);
        }
    }

    std::uint64_t ReserveNextSequence()
    {
        ++sequence_;

        ESP_ERROR_CHECK(nvs_set_u64(handle_, "seq", sequence_));
        ESP_ERROR_CHECK(nvs_commit(handle_));

        return sequence_;
    }

    Bytes FindCommandResult(std::string_view commandId) const
    {
        for (std::size_t index = 0; index < count_; ++index) {
            if (commandId == cache_[index].commandId) {
                return Bytes(
                    cache_[index].payload.begin(),
                    cache_[index].payload.begin() + cache_[index].payloadLength);
            }
        }

        return {};
    }

    void StoreCommandResult(
        std::string_view commandId,
        const Bytes &payload)
    {
        if (commandId.size() > CommandIdMaxBytes ||
            payload.size() > CommandResultMaxBytes) {
            abort();
        }

        if (count_ == cache_.size()) {
            std::move(cache_.begin() + 1, cache_.end(), cache_.begin());
            --count_;
        }

        auto &entry = cache_[count_++];
        entry = {};

        std::memcpy(entry.commandId, commandId.data(), commandId.size());
        entry.payloadLength = static_cast<std::uint16_t>(payload.size());
        std::copy(payload.begin(), payload.end(), entry.payload.begin());

        ESP_ERROR_CHECK(nvs_set_blob(
            handle_,
            "results",
            cache_.data(),
            count_ * sizeof(CommandCacheEntry)));

        ESP_ERROR_CHECK(nvs_commit(handle_));
    }

private:
    nvs_handle_t handle_{};
    std::uint64_t sequence_{};
    std::array<CommandCacheEntry, CommandCacheCapacity> cache_{};
    std::size_t count_{};
};

static DurableState durableState;


// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
// ============================================================================

class SessionState {
public:
    void Initialize()
    {
        mutex_ = xSemaphoreCreateMutex();
        if (mutex_ == nullptr) {
            abort();
        }
    }

    void Clear()
    {
        Lock lock(*this);
        key_.fill(0);
        authenticated_ = false;
    }

    void SetKey(const std::array<std::uint8_t, 32> &key)
    {
        Lock lock(*this);
        key_ = key;
    }

    std::array<std::uint8_t, 32> CopyKey() const
    {
        Lock lock(*this);
        return key_;
    }

    bool IsAuthenticated() const
    {
        Lock lock(*this);
        return authenticated_;
    }

    void MarkAuthenticated()
    {
        Lock lock(*this);
        authenticated_ = true;
    }

private:
    class Lock {
    public:
        explicit Lock(const SessionState &owner) : owner_(owner)
        {
            xSemaphoreTake(owner_.mutex_, portMAX_DELAY);
        }

        ~Lock()
        {
            xSemaphoreGive(owner_.mutex_);
        }

    private:
        const SessionState &owner_;
    };

    mutable SemaphoreHandle_t mutex_{};
    std::array<std::uint8_t, 32> key_{};
    bool authenticated_{};
};

static SessionState sessionState;

static std::uint64_t CurrentUnixTimeMs()
{
    timeval now{};
    gettimeofday(&now, nullptr);

    return static_cast<std::uint64_t>(now.tv_sec) * 1000ULL +
           static_cast<std::uint64_t>(now.tv_usec) / 1000ULL;
}

static void EncodeUint64BigEndian(std::uint8_t *destination, std::uint64_t value)
{
    for (int index = 7; index >= 0; --index) {
        destination[index] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
}

static bool ComputeAuthenticationProof(
    const std::array<std::uint8_t, 16> &serverNonce,
    const std::array<std::uint8_t, 16> &clientNonce,
    std::array<std::uint8_t, 32> &proof)
{
    Bytes message;
    message.reserve(32 + std::strlen(ScadaConfig::clientId));

    message.insert(message.end(), serverNonce.begin(), serverNonce.end());
    message.insert(message.end(), clientNonce.begin(), clientNonce.end());
    message.insert(
        message.end(),
        ScadaConfig::clientId,
        ScadaConfig::clientId + std::strlen(ScadaConfig::clientId));

    const mbedtls_md_info_t *sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    return mbedtls_md_hmac(
               sha256,
               reinterpret_cast<const std::uint8_t *>(ScadaConfig::apiToken),
               std::strlen(ScadaConfig::apiToken),
               message.data(),
               message.size(),
               proof.data()) == 0;
}

static bool DeriveSessionKey(
    const std::array<std::uint8_t, 16> &serverNonce,
    const std::array<std::uint8_t, 16> &clientNonce,
    std::array<std::uint8_t, 32> &derivedKey)
{
    std::array<std::uint8_t, 32> salt{};
    std::copy(serverNonce.begin(), serverNonce.end(), salt.begin());
    std::copy(clientNonce.begin(), clientNonce.end(), salt.begin() + 16);

    static constexpr std::uint8_t Info[] = "SCADA-ENC-v1";

    const mbedtls_md_info_t *sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    return mbedtls_hkdf(
               sha256,
               salt.data(),
               salt.size(),
               reinterpret_cast<const std::uint8_t *>(ScadaConfig::apiToken),
               std::strlen(ScadaConfig::apiToken),
               Info,
               sizeof(Info) - 1,
               derivedKey.data(),
               derivedKey.size()) == 0;
}


// ============================================================================
// STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
// ============================================================================

static Bytes CopyMessagePackBuffer(const msgpack_sbuffer &buffer)
{
    auto begin = reinterpret_cast<const std::uint8_t *>(buffer.data);
    return Bytes(begin, begin + buffer.size);
}

static void PackString(msgpack_packer &packer, std::string_view value)
{
    msgpack_pack_str(&packer, value.size());
    msgpack_pack_str_body(&packer, value.data(), value.size());
}

static void PackBinary(
    msgpack_packer &packer,
    const std::uint8_t *data,
    std::size_t length)
{
    msgpack_pack_bin(&packer, length);
    msgpack_pack_bin_body(&packer, data, length);
}

static bool ReadString(msgpack_object object, std::string &value)
{
    if (object.type != MSGPACK_OBJECT_STR) {
        return false;
    }

    value.assign(object.via.str.ptr, object.via.str.size);
    return true;
}

static bool ReadBinary(msgpack_object object, Bytes &value)
{
    if (object.type != MSGPACK_OBJECT_BIN) {
        return false;
    }

    const auto *begin =
        reinterpret_cast<const std::uint8_t *>(object.via.bin.ptr);

    value.assign(begin, begin + object.via.bin.size);
    return true;
}

static bool ReadUInt64(msgpack_object object, std::uint64_t &value)
{
    if (object.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return false;
    }

    value = object.via.u64;
    return true;
}

static bool ReadOutputBit(msgpack_object object, int &value)
{
    if (object.type == MSGPACK_OBJECT_BOOLEAN) {
        value = object.via.boolean ? 1 : 0;
        return true;
    }

    if (object.type == MSGPACK_OBJECT_POSITIVE_INTEGER && object.via.u64 <= 1) {
        value = static_cast<int>(object.via.u64);
        return true;
    }

    if ((object.type == MSGPACK_OBJECT_FLOAT32 ||
         object.type == MSGPACK_OBJECT_FLOAT64) &&
        (object.via.f64 == 0.0 || object.via.f64 == 1.0)) {
        value = static_cast<int>(object.via.f64);
        return true;
    }

    return false;
}

static std::array<std::uint8_t, 16> BuildAad(
    std::uint64_t sequence,
    std::uint64_t timestampMs)
{
    std::array<std::uint8_t, 16> aad{};
    EncodeUint64BigEndian(aad.data(), sequence);
    EncodeUint64BigEndian(aad.data() + 8, timestampMs);
    return aad;
}

static bool EncryptAesGcm(
    const std::array<std::uint8_t, 32> &key,
    const Bytes &plaintext,
    const std::array<std::uint8_t, 12> &nonce,
    const std::array<std::uint8_t, 16> &aad,
    Bytes &ciphertext,
    std::array<std::uint8_t, 16> &tag)
{
    ciphertext.resize(plaintext.size());

    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    int result = mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key.data(),
        256);

    if (result == 0) {
        result = mbedtls_gcm_crypt_and_tag(
            &context,
            MBEDTLS_GCM_ENCRYPT,
            plaintext.size(),
            nonce.data(),
            nonce.size(),
            aad.data(),
            aad.size(),
            plaintext.data(),
            ciphertext.data(),
            tag.size(),
            tag.data());
    }

    mbedtls_gcm_free(&context);
    return result == 0;
}

static bool DecryptAesGcm(
    const std::array<std::uint8_t, 32> &key,
    const Bytes &ciphertext,
    const Bytes &nonce,
    const std::array<std::uint8_t, 16> &aad,
    const Bytes &tag,
    Bytes &plaintext)
{
    if (nonce.size() != 12 || tag.size() != 16) {
        return false;
    }

    plaintext.resize(ciphertext.size());

    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    int result = mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key.data(),
        256);

    if (result == 0) {
        result = mbedtls_gcm_auth_decrypt(
            &context,
            ciphertext.size(),
            nonce.data(),
            nonce.size(),
            aad.data(),
            aad.size(),
            tag.data(),
            tag.size(),
            ciphertext.data(),
            plaintext.data());
    }

    mbedtls_gcm_free(&context);
    return result == 0;
}

static Bytes BuildAuthResponse(
    const std::array<std::uint8_t, 16> &clientNonce,
    const std::array<std::uint8_t, 32> &proof)
{
    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    msgpack_pack_array(&packer, 2);
    PackBinary(packer, clientNonce.data(), clientNonce.size());
    PackBinary(packer, proof.data(), proof.size());

    Bytes result = CopyMessagePackBuffer(buffer);
    msgpack_sbuffer_destroy(&buffer);
    return result;
}

static Bytes BuildTelemetry(int inputValue)
{
    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    // TagFrameBatchDto [ Frames, TraceId|null, SchemaVersion=1 ]
    msgpack_pack_array(&packer, 3);
    msgpack_pack_array(&packer, 1);

    // TagFrameDto [ Address, ValNum, ValStr, TsUnixMs, Quality ]
    msgpack_pack_array(&packer, 5);
    PackString(packer, ScadaConfig::InputTag);
    msgpack_pack_double(&packer, static_cast<double>(inputValue));
    msgpack_pack_nil(&packer);
    msgpack_pack_int64(&packer, 0);
    msgpack_pack_int(&packer, 192);

    msgpack_pack_nil(&packer);
    msgpack_pack_int(&packer, 1);

    Bytes result = CopyMessagePackBuffer(buffer);
    msgpack_sbuffer_destroy(&buffer);
    return result;
}

static Bytes BuildCommandResult(
    std::string_view commandId,
    bool success,
    std::string_view error,
    int appliedValue)
{
    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    msgpack_pack_array(&packer, 5);
    PackString(packer, commandId);

    success ? msgpack_pack_true(&packer) : msgpack_pack_false(&packer);

    if (error.empty()) {
        msgpack_pack_nil(&packer);
    } else {
        PackString(packer, error);
    }

    if (success) {
        std::string data =
            std::string("{\"appliedValue\":") +
            std::to_string(appliedValue) +
            "}";

        PackString(packer, data);
    } else {
        msgpack_pack_nil(&packer);
    }

    msgpack_pack_int(&packer, 1);

    Bytes result = CopyMessagePackBuffer(buffer);
    msgpack_sbuffer_destroy(&buffer);
    return result;
}

static Bytes EncryptEnvelope(const Bytes &innerPayload)
{
    std::uint64_t sequence = durableState.ReserveNextSequence();
    std::uint64_t timestampMs = CurrentUnixTimeMs();

    std::array<std::uint8_t, 12> nonce{};
    esp_fill_random(nonce.data(), nonce.size());

    auto aad = BuildAad(sequence, timestampMs);
    auto key = sessionState.CopyKey();

    Bytes ciphertext;
    std::array<std::uint8_t, 16> tag{};

    if (!EncryptAesGcm(key, innerPayload, nonce, aad, ciphertext, tag)) {
        abort();
    }

    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    msgpack_pack_array(&packer, 6);
    PackString(packer, ScadaConfig::keyId);
    PackBinary(packer, nonce.data(), nonce.size());
    PackBinary(packer, ciphertext.data(), ciphertext.size());
    PackBinary(packer, tag.data(), tag.size());
    msgpack_pack_uint64(&packer, sequence);
    msgpack_pack_uint64(&packer, timestampMs);

    Bytes envelope = CopyMessagePackBuffer(buffer);
    msgpack_sbuffer_destroy(&buffer);
    return envelope;
}

static bool DecryptEnvelope(const Bytes &envelope, Bytes &plaintext)
{
    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    std::size_t offset = 0;
    bool parsed = msgpack_unpack_next(
        &unpacked,
        reinterpret_cast<const char *>(envelope.data()),
        envelope.size(),
        &offset);

    if (!parsed ||
        unpacked.data.type != MSGPACK_OBJECT_ARRAY ||
        unpacked.data.via.array.size != 6) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    auto *fields = unpacked.data.via.array.ptr;

    std::string envelopeKeyId;
    Bytes nonce;
    Bytes ciphertext;
    Bytes tag;
    std::uint64_t sequence{};
    std::uint64_t timestampMs{};

    bool valid =
        ReadString(fields[0], envelopeKeyId) &&
        envelopeKeyId == ScadaConfig::keyId &&
        ReadBinary(fields[1], nonce) &&
        nonce.size() == 12 &&
        ReadBinary(fields[2], ciphertext) &&
        ReadBinary(fields[3], tag) &&
        tag.size() == 16 &&
        ReadUInt64(fields[4], sequence) &&
        ReadUInt64(fields[5], timestampMs);

    if (!valid) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    auto key = sessionState.CopyKey();
    auto aad = BuildAad(sequence, timestampMs);

    bool decrypted =
        DecryptAesGcm(key, ciphertext, nonce, aad, tag, plaintext);

    msgpack_unpacked_destroy(&unpacked);
    return decrypted;
}


// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
// ============================================================================

static esp_mqtt_client_handle_t mqttClient{};
static int challengeSubscriptionId = -1;
static int commandSubscriptionId = -1;
static bool challengeSubscriptionGranted = false;

static bool PublishQos1(const char *topic, const Bytes &payload)
{
    int messageId = esp_mqtt_client_publish(
        mqttClient,
        topic,
        reinterpret_cast<const char *>(payload.data()),
        static_cast<int>(payload.size()),
        1,
        0);

    return messageId >= 0;
}

static bool PublishEncryptedQos1(const char *topic, const Bytes &innerPayload)
{
    Bytes envelope = EncryptEnvelope(innerPayload);
    return PublishQos1(topic, envelope);
}

static bool AuthenticateFromChallenge(const Bytes &payload)
{
    if (!challengeSubscriptionGranted) {
        return false;
    }

    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    std::size_t offset = 0;
    bool parsed = msgpack_unpack_next(
        &unpacked,
        reinterpret_cast<const char *>(payload.data()),
        payload.size(),
        &offset);

    if (!parsed ||
        unpacked.data.type != MSGPACK_OBJECT_ARRAY ||
        unpacked.data.via.array.size != 2) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    auto *fields = unpacked.data.via.array.ptr;

    Bytes serverNonceBytes;
    std::uint64_t expiresAtMs{};

    bool valid =
        ReadBinary(fields[0], serverNonceBytes) &&
        serverNonceBytes.size() == 16 &&
        ReadUInt64(fields[1], expiresAtMs) &&
        CurrentUnixTimeMs() < expiresAtMs;

    if (!valid) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    std::array<std::uint8_t, 16> serverNonce{};
    std::copy(serverNonceBytes.begin(), serverNonceBytes.end(), serverNonce.begin());

    std::array<std::uint8_t, 16> clientNonce{};
    std::array<std::uint8_t, 32> proof{};
    std::array<std::uint8_t, 32> derivedKey{};

    esp_fill_random(clientNonce.data(), clientNonce.size());

    if (!ComputeAuthenticationProof(serverNonce, clientNonce, proof) ||
        !DeriveSessionKey(serverNonce, clientNonce, derivedKey)) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    sessionState.SetKey(derivedKey);

    Bytes response = BuildAuthResponse(clientNonce, proof);
    if (!PublishQos1(ScadaConfig::authResponseTopic, response)) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    // Promotion proof: require a successful post-auth command SUBACK.
    commandSubscriptionId =
        esp_mqtt_client_subscribe(
            mqttClient,
            ScadaConfig::commandsTopic,
            1);

    msgpack_unpacked_destroy(&unpacked);
    return commandSubscriptionId >= 0;
}

static void PublishTelemetry()
{
    if (!sessionState.IsAuthenticated()) {
        return;
    }

    Bytes telemetry = BuildTelemetry(digitalIo.ReadInput());

    if (!PublishEncryptedQos1(ScadaConfig::telemetryTopic, telemetry)) {
        ESP_LOGW(LogTag, "Telemetry publish could not be queued");
    }
}


// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
// ============================================================================

static void HandleCommand(const Bytes &encryptedPayload)
{
    Bytes plaintext;
    if (!DecryptEnvelope(encryptedPayload, plaintext)) {
        ESP_LOGW(LogTag, "Rejected command envelope");
        return;
    }

    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    std::size_t offset = 0;
    bool parsed = msgpack_unpack_next(
        &unpacked,
        reinterpret_cast<const char *>(plaintext.data()),
        plaintext.size(),
        &offset);

    if (!parsed ||
        unpacked.data.type != MSGPACK_OBJECT_ARRAY ||
        unpacked.data.via.array.size != 10) {
        msgpack_unpacked_destroy(&unpacked);
        return;
    }

    auto *fields = unpacked.data.via.array.ptr;

    std::string commandId;
    std::string tagAddress;
    std::uint64_t expiryEpochSeconds{};
    std::uint64_t schemaVersion{};

    bool headerValid =
        ReadString(fields[0], commandId) &&
        !commandId.empty() &&
        commandId.size() <= CommandIdMaxBytes &&
        ReadString(fields[1], tagAddress) &&
        ReadUInt64(fields[4], expiryEpochSeconds) &&
        ReadUInt64(fields[9], schemaVersion);

    if (!headerValid) {
        msgpack_unpacked_destroy(&unpacked);
        return;
    }

    Bytes cached = durableState.FindCommandResult(commandId);
    if (!cached.empty()) {
        PublishEncryptedQos1(ScadaConfig::commandResultTopic, cached);
        msgpack_unpacked_destroy(&unpacked);
        return;
    }

    int requestedValue = 0;
    bool valueValid = ReadOutputBit(fields[2], requestedValue);

    bool confirmationTypesValid =
        fields[7].type == MSGPACK_OBJECT_BOOLEAN &&
        fields[8].type == MSGPACK_OBJECT_BOOLEAN;

    std::string error;

    if (schemaVersion != 2) {
        error = "unsupported command schema";
    } else if (tagAddress != ScadaConfig::OutputTag) {
        error = "unsupported command address";
    } else if (expiryEpochSeconds <= CurrentUnixTimeMs() / 1000ULL) {
        error = "command expired";
    } else if (!confirmationTypesValid) {
        error = "invalid confirmation flags";
    } else if (fields[7].via.boolean && !fields[8].via.boolean) {
        error = "operator confirmation required";
    } else if (!valueValid) {
        error = "do.output1 accepts only 0 or 1";
    } else if (!digitalIo.WriteOutput(requestedValue)) {
        error = "local output write failed";
    }

    bool success = error.empty();
    Bytes result = BuildCommandResult(
        commandId,
        success,
        error,
        requestedValue);

    durableState.StoreCommandResult(commandId, result);
    PublishEncryptedQos1(ScadaConfig::commandResultTopic, result);

    msgpack_unpacked_destroy(&unpacked);
}


// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
// ============================================================================

static std::array<std::uint8_t, ScadaConfig::MaxIncomingPayloadBytes> incomingPayload{};
static int incomingTotalLength = 0;
static int incomingReceivedLength = 0;
static std::array<char, 512> incomingTopic{};

static bool SubscriptionGrantedQos1(esp_mqtt_event_handle_t event)
{
    return event->error_handle != nullptr &&
           event->error_handle->error_type == MQTT_ERROR_TYPE_NONE &&
           event->data_len == 1 &&
           static_cast<std::uint8_t>(event->data[0]) == 0x01;
}

static void ResetApplicationSession()
{
    sessionState.Clear();
    challengeSubscriptionGranted = false;
    challengeSubscriptionId = -1;
    commandSubscriptionId = -1;
}

static void DispatchCompletePublish()
{
    std::string_view topic(incomingTopic.data());
    Bytes payload(
        incomingPayload.begin(),
        incomingPayload.begin() + incomingTotalLength);

    if (topic == ScadaConfig::authChallengeTopic) {
        AuthenticateFromChallenge(payload);
        return;
    }

    if (topic == ScadaConfig::commandsTopic && sessionState.IsAuthenticated()) {
        HandleCommand(payload);
    }
}

static void MqttEventHandler(
    void *,
    esp_event_base_t,
    std::int32_t eventId,
    void *eventData)
{
    auto *event = static_cast<esp_mqtt_event_handle_t>(eventData);

    switch (static_cast<esp_mqtt_event_id_t>(eventId)) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(LogTag, "MQTT connected; starting a new SCADALGERIA session");

            ResetApplicationSession();

            challengeSubscriptionId =
                esp_mqtt_client_subscribe(
                    mqttClient,
                    ScadaConfig::authChallengeTopic,
                    1);

            if (challengeSubscriptionId < 0) {
                ESP_LOGE(LogTag, "Could not subscribe to auth challenge topic");
            }
            break;

        case MQTT_EVENT_SUBSCRIBED:
            if (event->msg_id == challengeSubscriptionId) {
                if (!SubscriptionGrantedQos1(event)) {
                    ESP_LOGE(LogTag, "Auth challenge subscription was refused");
                    ResetApplicationSession();
                    break;
                }

                challengeSubscriptionGranted = true;
                break;
            }

            if (event->msg_id == commandSubscriptionId) {
                if (!SubscriptionGrantedQos1(event)) {
                    ESP_LOGE(LogTag, "Post-auth command subscription was refused");
                    ResetApplicationSession();
                    break;
                }

                sessionState.MarkAuthenticated();
                ESP_LOGI(LogTag, "SCADALGERIA application session authenticated");
            }
            break;

        case MQTT_EVENT_DATA:
            if (event->current_data_offset == 0) {
                incomingTotalLength = event->total_data_len;
                incomingReceivedLength = 0;

                if (incomingTotalLength <= 0 ||
                    incomingTotalLength > static_cast<int>(incomingPayload.size()) ||
                    event->topic_len <= 0 ||
                    event->topic_len >= static_cast<int>(incomingTopic.size())) {
                    incomingTotalLength = 0;
                    break;
                }

                std::memcpy(incomingTopic.data(), event->topic, event->topic_len);
                incomingTopic[event->topic_len] = '\0';
            }

            if (incomingTotalLength == 0 ||
                event->current_data_offset < 0 ||
                event->data_len < 0 ||
                event->current_data_offset + event->data_len > incomingTotalLength) {
                break;
            }

            std::memcpy(
                incomingPayload.data() + event->current_data_offset,
                event->data,
                event->data_len);

            incomingReceivedLength = std::max(
                incomingReceivedLength,
                event->current_data_offset + event->data_len);

            if (incomingReceivedLength == incomingTotalLength) {
                DispatchCompletePublish();
                incomingTotalLength = 0;
                incomingReceivedLength = 0;
            }
            break;

        case MQTT_EVENT_DISCONNECTED:
        case MQTT_EVENT_ERROR:
            ResetApplicationSession();
            break;

        default:
            break;
    }
}

static void TelemetryTask(void *)
{
    for (;;) {
        if (sessionState.IsAuthenticated()) {
            PublishTelemetry();
        }

        // Replace this fixed example cadence with the server-issued
        // the copied configuration telemetryPolicy in a production device.
        vTaskDelay(pdMS_TO_TICKS(ScadaConfig::TelemetryIntervalMs));
    }
}

extern "C" void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());

    ScadaConfig::LoadProvisioning();
    durableState.Initialize();
    digitalIo.Initialize();
    sessionState.Initialize();

    esp_mqtt_client_config_t mqttConfig{};

    mqttConfig.broker.address.hostname = ScadaConfig::mqttHost;
    mqttConfig.broker.address.port = ScadaConfig::mqttPort;
    mqttConfig.broker.address.transport = MQTT_TRANSPORT_OVER_TCP;

    mqttConfig.credentials.client_id = ScadaConfig::clientId;
    mqttConfig.credentials.username = ScadaConfig::mqttUsername;
    mqttConfig.credentials.authentication.password = "";

    // platform's current Direct Firmware protocol requires MQTT 3.1.1 and
    // CleanSession=true. In ESP-MQTT the latter means disable_clean_session=false.
    mqttConfig.session.protocol_ver = MQTT_PROTOCOL_V_3_1_1;
    mqttConfig.session.disable_clean_session = false;

    mqttClient = esp_mqtt_client_init(&mqttConfig);
    if (mqttClient == nullptr) {
        abort();
    }

    ESP_ERROR_CHECK(esp_mqtt_client_register_event(
        mqttClient,
        ESP_EVENT_ANY_ID,
        MqttEventHandler,
        nullptr));

    ESP_ERROR_CHECK(esp_mqtt_client_start(mqttClient));

    xTaskCreate(
        TelemetryTask,
        "scada_telemetry",
        6144,
        nullptr,
        5,
        nullptr);
}
