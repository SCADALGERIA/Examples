/*
 * SCADALGERIA Direct Firmware example — C++ / ESP32 / Arduino
 *
 * Target stack used by the companion README:
 *   Arduino-ESP32 3.3.12
 *   ArduinoMqttClient 0.1.8
 *   MsgPack 0.4.2
 *
 * This is intentionally a readable single-file integration snippet. The
 * surrounding product firmware still owns Wi-Fi provisioning, OTA, watchdogs,
 * secure credential provisioning, and production device-health behavior.
 *
 * Demonstrated flow:
 *
 *   GPIO4 -> "di.input1" telemetry
 *   SCADALGERIA platform -> "do.output1" command -> GPIO18
 *   command outcome -> encrypted CommandResultDto
 */

// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

#include <Arduino.h>
#include <ArduinoMqttClient.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <MsgPack.h>
#include <Preferences.h>
#include <WiFi.h>

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <time.h>
#include <sys/time.h>
#include <vector>

using Bytes = std::vector<std::uint8_t>;


// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
// ============================================================================
//
// Store Connection → Copy firmware configuration → Copy JSON as
// `/scadalgeria-connection.json` in LittleFS.
// Store the API-key secret separately in Preferences namespace `scada_secret`,
// key `api_key`. Never add the secret to the copied JSON.

constexpr const char *CONNECTION_CONFIG_FILE = "/scadalgeria-connection.json";
constexpr const char *INPUT_TAG_ADDRESS = "di.input1";
constexpr const char *OUTPUT_TAG_ADDRESS = "do.output1";
constexpr int INPUT_PIN = 4;
constexpr int OUTPUT_PIN = 18;
constexpr unsigned long TELEMETRY_INTERVAL_MS = 1000;
constexpr unsigned long INITIAL_RECONNECT_DELAY_MS = 1000;
constexpr unsigned long MAX_RECONNECT_DELAY_MS = 30000;

char clientId[32]{};
char mqttHost[256]{};
std::uint16_t mqttPort = 0;
char mqttUsername[384]{};
char keyId[64]{};
char apiToken[512]{};
char authChallengeTopic[512]{};
char authResponseTopic[512]{};
char telemetryTopic[512]{};
char commandsTopic[512]{};
char commandResultTopic[512]{};

static void CopyRequiredString(JsonObjectConst object, const char *name, char *destination, std::size_t capacity)
{
    const char *value = object[name] | nullptr;
    if (value == nullptr || *value == '\0' || strlen(value) + 1 > capacity) {
        Serial.printf("Missing/invalid copied configuration field: %s\n", name);
        abort();
    }
    strlcpy(destination, value, capacity);
}

static void CreateUniqueClientId()
{
    std::uint8_t random[8];
    esp_fill_random(random, sizeof(random));
    static constexpr char Hex[] = "0123456789abcdef";
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
    if (marker == nullptr || strstr(marker + 10, "{clientId}") != nullptr) abort();
    const std::size_t prefix = static_cast<std::size_t>(marker - topicTemplate);
    const int written = snprintf(destination, capacity, "%.*s%s%s", static_cast<int>(prefix), topicTemplate, clientId, marker + 10);
    if (written < 0 || static_cast<std::size_t>(written) >= capacity) abort();
}

static void RequireBooleanTag(JsonArrayConst tags, const char *address, const char *direction)
{
    int matches = 0;
    for (JsonObjectConst tag : tags) {
        const char *tagAddress = tag["address"] | "";
        if (strcmp(tagAddress, address) == 0) {
            ++matches;
            if (strcmp(tag["dataType"] | "", "Boolean") != 0 || strcmp(tag["direction"] | "", direction) != 0) abort();
        }
    }
    if (matches != 1) abort();
}

static void LoadScadalgeriaProvisioning()
{
    if (!LittleFS.begin(true)) abort();
    File file = LittleFS.open(CONNECTION_CONFIG_FILE, "r");
    if (!file) abort();

    JsonDocument document;
    if (deserializeJson(document, file) != DeserializationError::Ok) abort();
    file.close();

    JsonObjectConst root = document.as<JsonObjectConst>();
    if (strcmp(root["schema"] | "", "scadalgeria.direct-firmware.connection") != 0 || (root["schemaVersion"] | 0) != 1) abort();

    JsonObjectConst connection = root["connection"];
    JsonObjectConst identity = root["identity"];
    JsonObjectConst mqtt = root["mqtt"];
    JsonObjectConst broker = mqtt["broker"];
    JsonObjectConst topics = mqtt["topics"];
    JsonObjectConst qos = mqtt["qos"];
    JsonObjectConst authentication = root["authentication"];
    JsonObjectConst encryption = root["encryption"];
    JsonObjectConst kdf = encryption["sessionKeyDerivation"];
    JsonObjectConst secrets = root["secrets"];

    if (!(connection["enabled"] | false)) abort();
    if (strcmp(mqtt["protocol"] | "", "3.1.1") != 0 || !(mqtt["cleanSession"] | false)) abort();
    if (strcmp(broker["transport"] | "", "tcp") != 0) abort();
    if (strcmp(mqtt["clientIdRequirement"] | "", "unique-per-active-session") != 0) abort();
    if ((qos["telemetry"] | 0) != 1 || (qos["commands"] | 0) != 1 || (qos["commandResults"] | 0) != 1) abort();
    if (strcmp(authentication["scheme"] | "", "HMAC-SHA256") != 0 || strcmp(encryption["scheme"] | "", "AES-256-GCM") != 0) abort();
    if (strcmp(kdf["algorithm"] | "", "HKDF-SHA256") != 0 || strcmp(kdf["info"] | "", "SCADA-ENC-v1") != 0) abort();
    if (secrets["apiKeySecretIncluded"] | true) abort();

    RequireBooleanTag(root["tags"].as<JsonArrayConst>(), INPUT_TAG_ADDRESS, "Input");
    RequireBooleanTag(root["tags"].as<JsonArrayConst>(), OUTPUT_TAG_ADDRESS, "Output");
    CreateUniqueClientId();

    CopyRequiredString(broker, "host", mqttHost, sizeof(mqttHost));
    mqttPort = broker["port"] | 0;
    CopyRequiredString(mqtt, "username", mqttUsername, sizeof(mqttUsername));
    CopyRequiredString(identity, "keyId", keyId, sizeof(keyId));

    char challengeTemplate[512]{};
    char responseTemplate[512]{};
    CopyRequiredString(topics, "authenticationChallenge", challengeTemplate, sizeof(challengeTemplate));
    CopyRequiredString(topics, "authenticationResponse", responseTemplate, sizeof(responseTemplate));
    ResolveClientTopic(challengeTemplate, authChallengeTopic, sizeof(authChallengeTopic));
    ResolveClientTopic(responseTemplate, authResponseTopic, sizeof(authResponseTopic));
    CopyRequiredString(topics, "telemetry", telemetryTopic, sizeof(telemetryTopic));
    CopyRequiredString(topics, "commands", commandsTopic, sizeof(commandsTopic));
    CopyRequiredString(topics, "commandResults", commandResultTopic, sizeof(commandResultTopic));

    Preferences secretsStore;
    if (!secretsStore.begin("scada_secret", true)) abort();
    String secret = secretsStore.getString("api_key", "");
    secretsStore.end();
    if (secret.isEmpty() || secret.length() + 1 > sizeof(apiToken)) abort();
    strlcpy(apiToken, secret.c_str(), sizeof(apiToken));
}


// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
// ============================================================================
//
// Example wiring:
//   GPIO4  -> dry contact / push-button to GND. INPUT_PULLUP makes it active-low.
//   GPIO18 -> LED or appropriately isolated logic-level input.
//
// Never drive industrial field voltage, relay coils, motors, or contactors
// directly from ESP32 GPIO.

static void InitializeDigitalIo()
{
    pinMode(INPUT_PIN, INPUT_PULLUP);
    pinMode(OUTPUT_PIN, OUTPUT);

    // Safe initial state for the example.
    digitalWrite(OUTPUT_PIN, LOW);
}

static int ReadDigitalInput()
{
    return digitalRead(INPUT_PIN) == LOW ? 1 : 0;
}

static bool WriteDigitalOutput(int value)
{
    if (value != 0 && value != 1) {
        return false;
    }

    digitalWrite(OUTPUT_PIN, value == 1 ? HIGH : LOW);
    return true;
}


// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
// ============================================================================
//
// Device->platform Seq must survive MQTT reconnects and ESP32 reboots.
// Persist it before using a new logical message.
//
// We also persist the final *inner* command result by command Id. If MQTT or
// the command pipeline redelivers the same Id, we return the stored result
// instead of operating GPIO18 a second time.

constexpr std::size_t COMMAND_CACHE_CAPACITY = 12;
constexpr std::size_t COMMAND_RESULT_MAX_BYTES = 384;
constexpr std::size_t COMMAND_ID_MAX_BYTES = 80;

struct CommandCacheEntry {
    char commandId[COMMAND_ID_MAX_BYTES + 1]{};
    std::uint16_t payloadLength{};
    std::array<std::uint8_t, COMMAND_RESULT_MAX_BYTES> payload{};
};

Preferences statePreferences;
std::array<CommandCacheEntry, COMMAND_CACHE_CAPACITY> commandCache{};
std::size_t commandCacheCount = 0;

static void LoadDurableState()
{
    if (!statePreferences.begin("scada", false)) {
        abort();
    }

    std::size_t cacheBytes = statePreferences.getBytesLength("results");

    if (cacheBytes == 0) {
        commandCacheCount = 0;
        return;
    }

    if (cacheBytes > sizeof(commandCache) ||
        cacheBytes % sizeof(CommandCacheEntry) != 0) {
        Serial.println("Persisted command-result cache is malformed");
        abort();
    }

    statePreferences.getBytes(
        "results",
        commandCache.data(),
        cacheBytes);

    commandCacheCount = cacheBytes / sizeof(CommandCacheEntry);
}

static std::uint64_t ReserveNextOutgoingSequence()
{
    std::uint64_t nextSequence =
        statePreferences.getULong64("seq", 0) + 1;

    // Preferences::putULong64 returns the number of bytes written.
    if (statePreferences.putULong64("seq", nextSequence) != sizeof(nextSequence)) {
        abort();
    }

    return nextSequence;
}

static Bytes FindCachedCommandResult(const String &commandId)
{
    for (std::size_t index = 0; index < commandCacheCount; ++index) {
        if (commandId.equals(commandCache[index].commandId)) {
            return Bytes(
                commandCache[index].payload.begin(),
                commandCache[index].payload.begin() +
                    commandCache[index].payloadLength);
        }
    }

    return {};
}

static void PersistCommandResult(
    const String &commandId,
    const Bytes &payload)
{
    if (commandId.length() > COMMAND_ID_MAX_BYTES ||
        payload.size() > COMMAND_RESULT_MAX_BYTES) {
        abort();
    }

    if (commandCacheCount == commandCache.size()) {
        std::move(
            commandCache.begin() + 1,
            commandCache.end(),
            commandCache.begin());

        --commandCacheCount;
    }

    auto &entry = commandCache[commandCacheCount++];
    entry = {};

    std::memcpy(entry.commandId, commandId.c_str(), commandId.length());
    entry.payloadLength = static_cast<std::uint16_t>(payload.size());
    std::copy(payload.begin(), payload.end(), entry.payload.begin());

    std::size_t bytesToPersist = commandCacheCount * sizeof(CommandCacheEntry);

    if (statePreferences.putBytes(
            "results",
            commandCache.data(),
            bytesToPersist) != bytesToPersist) {
        abort();
    }
}


// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
// ============================================================================

WiFiClient networkClient;
MqttClient mqtt(networkClient);

std::array<std::uint8_t, 32> sessionKey{};
bool authenticated = false;

static void ClearApplicationSession()
{
    sessionKey.fill(0);
    authenticated = false;
}

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
    const Bytes &serverNonce,
    const std::array<std::uint8_t, 16> &clientNonce,
    std::array<std::uint8_t, 32> &proof)
{
    if (serverNonce.size() != 16) {
        return false;
    }

    Bytes message;
    message.reserve(32 + std::strlen(clientId));

    message.insert(message.end(), serverNonce.begin(), serverNonce.end());
    message.insert(message.end(), clientNonce.begin(), clientNonce.end());
    message.insert(
        message.end(),
        clientId,
        clientId + std::strlen(clientId));

    const mbedtls_md_info_t *sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    return mbedtls_md_hmac(
               sha256,
               reinterpret_cast<const std::uint8_t *>(apiToken),
               std::strlen(apiToken),
               message.data(),
               message.size(),
               proof.data()) == 0;
}

static bool DeriveSessionKey(
    const Bytes &serverNonce,
    const std::array<std::uint8_t, 16> &clientNonce,
    std::array<std::uint8_t, 32> &derivedKey)
{
    if (serverNonce.size() != 16) {
        return false;
    }

    std::array<std::uint8_t, 32> salt{};
    std::copy(serverNonce.begin(), serverNonce.end(), salt.begin());
    std::copy(clientNonce.begin(), clientNonce.end(), salt.begin() + 16);

    static constexpr std::uint8_t HkdfInfo[] = "SCADA-ENC-v1";

    const mbedtls_md_info_t *sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    return mbedtls_hkdf(
               sha256,
               salt.data(),
               salt.size(),
               reinterpret_cast<const std::uint8_t *>(apiToken),
               std::strlen(apiToken),
               HkdfInfo,
               sizeof(HkdfInfo) - 1,
               derivedKey.data(),
               derivedKey.size()) == 0;
}


// ============================================================================
// STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
// ============================================================================

static Bytes CopyPackerBytes(const MsgPack::Packer &packer)
{
    return Bytes(packer.data(), packer.data() + packer.size());
}

static bool EncryptAesGcm(
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
        sessionKey.data(),
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
    const Bytes &ciphertext,
    const Bytes &nonce,
    const Bytes &tag,
    const std::array<std::uint8_t, 16> &aad,
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
        sessionKey.data(),
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

static std::array<std::uint8_t, 16> BuildAad(
    std::uint64_t sequence,
    std::uint64_t timestampMs)
{
    std::array<std::uint8_t, 16> aad{};
    EncodeUint64BigEndian(aad.data(), sequence);
    EncodeUint64BigEndian(aad.data() + 8, timestampMs);
    return aad;
}

static Bytes BuildAuthResponse(
    const std::array<std::uint8_t, 16> &clientNonce,
    const std::array<std::uint8_t, 32> &proof)
{
    MsgPack::Packer packer;

    // MqttAuthResponseDto = [ ClientNonce, Auth ]
    packer.packArraySize(2);
    packer.pack(clientNonce.data(), clientNonce.size());
    packer.pack(proof.data(), proof.size());

    return CopyPackerBytes(packer);
}

static Bytes BuildTelemetry(int inputValue)
{
    MsgPack::Packer packer;

    // TagFrameBatchDto = [ Frames, TraceId|null, SchemaVersion=1 ]
    packer.packArraySize(3);

    packer.packArraySize(1);

    // TagFrameDto = [ Address, ValNum, ValStr, TsUnixMs, Quality ]
    packer.packArraySize(5);
    packer.pack(INPUT_TAG_ADDRESS);
    packer.pack(static_cast<double>(inputValue));
    packer.pack(nullptr);
    packer.pack(static_cast<std::int64_t>(0));
    packer.pack(192);

    packer.pack(nullptr);
    packer.pack(1);

    return CopyPackerBytes(packer);
}

static Bytes BuildCommandResult(
    const String &commandId,
    bool success,
    const String &error,
    int appliedValue)
{
    MsgPack::Packer packer;

    // CommandResultDto = [ CommandId, Success, Error, Data, SchemaVersion=1 ]
    packer.packArraySize(5);
    packer.pack(commandId.c_str());
    packer.pack(success);

    if (error.length() > 0) {
        packer.pack(error.c_str());
    } else {
        packer.pack(nullptr);
    }

    if (success) {
        String data = String("{\"appliedValue\":") + appliedValue + "}";
        packer.pack(data.c_str());
    } else {
        packer.pack(nullptr);
    }

    packer.pack(1);
    return CopyPackerBytes(packer);
}

static Bytes EncryptEnvelope(const Bytes &innerPayload)
{
    std::uint64_t sequence = ReserveNextOutgoingSequence();
    std::uint64_t timestampMs = CurrentUnixTimeMs();

    std::array<std::uint8_t, 12> nonce{};
    esp_fill_random(nonce.data(), nonce.size());

    auto aad = BuildAad(sequence, timestampMs);

    Bytes ciphertext;
    std::array<std::uint8_t, 16> tag{};

    if (!EncryptAesGcm(innerPayload, nonce, aad, ciphertext, tag)) {
        abort();
    }

    MsgPack::Packer packer;

    packer.packArraySize(6);
    packer.pack(keyId);
    packer.pack(nonce.data(), nonce.size());
    packer.pack(ciphertext);
    packer.pack(tag.data(), tag.size());
    packer.pack(sequence);
    packer.pack(timestampMs);

    return CopyPackerBytes(packer);
}

static void SkipOneMessagePackValue(MsgPack::Unpacker &unpacker)
{
    // CommandDto contains Timestamp, nullable fields, and a dynamically typed
    // Value. The example only needs selected fields, so this helper advances
    // over one arbitrary MessagePack value without pretending it has a type.

    if (unpacker.isTimestamp()) {
        (void)unpacker.unpackTimestamp();
        return;
    }

    switch (unpacker.getType()) {
        case MsgPack::Type::NIL:
            (void)unpacker.unpackNil();
            return;

        case MsgPack::Type::BOOL:
            (void)unpacker.unpackBool();
            return;

        case MsgPack::Type::UINT7:
        case MsgPack::Type::UINT8:
        case MsgPack::Type::UINT16:
        case MsgPack::Type::UINT32:
        case MsgPack::Type::UINT64:
            (void)unpacker.unpackUInt<std::uint64_t>();
            return;

        case MsgPack::Type::INT5:
        case MsgPack::Type::INT8:
        case MsgPack::Type::INT16:
        case MsgPack::Type::INT32:
        case MsgPack::Type::INT64:
            (void)unpacker.unpackInt<std::int64_t>();
            return;

        case MsgPack::Type::FLOAT32:
        case MsgPack::Type::FLOAT64:
            (void)unpacker.unpackFloat<double>();
            return;

        case MsgPack::Type::STR5:
        case MsgPack::Type::STR8:
        case MsgPack::Type::STR16:
        case MsgPack::Type::STR32:
            (void)unpacker.unpackString();
            return;

        case MsgPack::Type::BIN8:
        case MsgPack::Type::BIN16:
        case MsgPack::Type::BIN32:
            (void)unpacker.unpackBinary<std::uint8_t>();
            return;

        case MsgPack::Type::ARRAY4:
        case MsgPack::Type::ARRAY16:
        case MsgPack::Type::ARRAY32: {
            std::size_t count = unpacker.unpackArraySize();
            while (count-- > 0) {
                SkipOneMessagePackValue(unpacker);
            }
            return;
        }

        case MsgPack::Type::MAP4:
        case MsgPack::Type::MAP16:
        case MsgPack::Type::MAP32: {
            std::size_t values = unpacker.unpackMapSize() * 2;
            while (values-- > 0) {
                SkipOneMessagePackValue(unpacker);
            }
            return;
        }

        default: {
            MsgPack::object::ext extension;
            unpacker.unpack(extension);
            return;
        }
    }
}

static bool ReadOutputBit(MsgPack::Unpacker &unpacker, int &outputValue)
{
    auto type = unpacker.getType();

    if (type == MsgPack::Type::BOOL) {
        outputValue = unpacker.unpackBool() ? 1 : 0;
        return true;
    }

    if (type == MsgPack::Type::FLOAT32 || type == MsgPack::Type::FLOAT64) {
        double value = unpacker.unpackFloat<double>();

        if (value == 0.0 || value == 1.0) {
            outputValue = static_cast<int>(value);
            return true;
        }

        return false;
    }

    switch (type) {
        case MsgPack::Type::UINT7:
        case MsgPack::Type::UINT8:
        case MsgPack::Type::UINT16:
        case MsgPack::Type::UINT32:
        case MsgPack::Type::UINT64:
        case MsgPack::Type::INT5:
        case MsgPack::Type::INT8:
        case MsgPack::Type::INT16:
        case MsgPack::Type::INT32:
        case MsgPack::Type::INT64: {
            std::int64_t value = unpacker.unpackInt<std::int64_t>();

            if (value == 0 || value == 1) {
                outputValue = static_cast<int>(value);
                return true;
            }

            return false;
        }

        default:
            SkipOneMessagePackValue(unpacker);
            return false;
    }
}

static bool DecryptEnvelope(const Bytes &envelope, Bytes &plaintext)
{
    MsgPack::Unpacker unpacker;

    if (!unpacker.feed(envelope.data(), envelope.size()) ||
        unpacker.unpackArraySize() != 6) {
        return false;
    }

    String envelopeKeyId = unpacker.unpackString().c_str();
    Bytes nonce = unpacker.unpackBinary<std::uint8_t>();
    Bytes ciphertext = unpacker.unpackBinary<std::uint8_t>();
    Bytes tag = unpacker.unpackBinary<std::uint8_t>();
    std::uint64_t sequence = unpacker.unpackUInt<std::uint64_t>();
    std::uint64_t timestampMs = unpacker.unpackUInt<std::uint64_t>();

    if (!unpacker.decoded() ||
        envelopeKeyId != keyId ||
        nonce.size() != 12 ||
        tag.size() != 16) {
        return false;
    }

    return DecryptAesGcm(
        ciphertext,
        nonce,
        tag,
        BuildAad(sequence, timestampMs),
        plaintext);
}


// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
// ============================================================================

static bool PublishQos1(const char *topic, const Bytes &payload)
{
    if (!mqtt.beginMessage(
            topic,
            static_cast<unsigned long>(payload.size()),
            false,  // retain
            1)) {   // QoS 1
        return false;
    }

    if (mqtt.write(payload.data(), payload.size()) != payload.size()) {
        mqtt.stop();
        return false;
    }

    // ArduinoMqttClient waits for PUBACK inside endMessage() for QoS1.
    return mqtt.endMessage() == 1;
}

static bool PublishEncryptedQos1(const char *topic, const Bytes &innerPayload)
{
    return PublishQos1(topic, EncryptEnvelope(innerPayload));
}

static bool AuthenticateFromChallenge(const Bytes &payload)
{
    MsgPack::Unpacker unpacker;

    if (!unpacker.feed(payload.data(), payload.size()) ||
        unpacker.unpackArraySize() != 2) {
        Serial.println("Rejected malformed SCADALGERIA auth challenge");
        return false;
    }

    Bytes serverNonce = unpacker.unpackBinary<std::uint8_t>();
    std::uint64_t expiresAtMs = unpacker.unpackUInt<std::uint64_t>();

    if (!unpacker.decoded() ||
        serverNonce.size() != 16 ||
        CurrentUnixTimeMs() >= expiresAtMs) {
        Serial.println("Rejected invalid or expired auth challenge");
        return false;
    }

    std::array<std::uint8_t, 16> clientNonce{};
    std::array<std::uint8_t, 32> proof{};
    std::array<std::uint8_t, 32> derivedKey{};

    esp_fill_random(clientNonce.data(), clientNonce.size());

    if (!ComputeAuthenticationProof(serverNonce, clientNonce, proof) ||
        !DeriveSessionKey(serverNonce, clientNonce, derivedKey)) {
        return false;
    }

    sessionKey = derivedKey;

    Bytes authResponse = BuildAuthResponse(clientNonce, proof);
    if (!PublishQos1(authResponseTopic, authResponse)) {
        return false;
    }

    // There is no custom AUTH_OK packet. Prove promotion by subscribing to
    // the exact post-auth command topic and requiring the granted QoS to be 1.
    if (!mqtt.subscribe(commandsTopic, 1) || mqtt.subscribeQoS() != 1) {
        Serial.println("The broker did not grant the post-auth command subscription");
        ClearApplicationSession();
        return false;
    }

    authenticated = true;
    Serial.println("SCADALGERIA application session authenticated");
    return true;
}

static void PublishTelemetry()
{
    if (!authenticated) {
        return;
    }

    Bytes telemetry = BuildTelemetry(ReadDigitalInput());

    if (!PublishEncryptedQos1(telemetryTopic, telemetry)) {
        Serial.println("Telemetry publish failed; reconnect will re-authenticate");
    }

    // MQTT PUBACK proves transport delivery only. the platform may still reject the
    // batch for replay, clock skew, ACL, tag/type/quality/range, or rate limits.
}


// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
// ============================================================================

static void HandleCommand(const Bytes &encryptedPayload)
{
    Bytes plaintext;

    if (!DecryptEnvelope(encryptedPayload, plaintext)) {
        Serial.println("Rejected command envelope: key/shape/GCM validation failed");
        return;
    }

    MsgPack::Unpacker unpacker;

    if (!unpacker.feed(plaintext.data(), plaintext.size()) ||
        unpacker.unpackArraySize() != 10) {
        Serial.println("Rejected malformed CommandDto");
        return;
    }

    String commandId = unpacker.unpackString().c_str();
    String tagAddress = unpacker.unpackString().c_str();

    if (!unpacker.decoded() || commandId.length() == 0) {
        return;
    }

    Bytes cachedResult = FindCachedCommandResult(commandId);
    if (!cachedResult.empty()) {
        PublishEncryptedQos1(commandResultTopic, cachedResult);
        return;
    }

    // CommandDto[2] = Value (dynamic). Read only 0/1 for this digital output.
    int requestedValue = 0;
    bool valueValid = ReadOutputBit(unpacker, requestedValue);

    // [3] Timestamp exists in the contract but is not needed for this action.
    SkipOneMessagePackValue(unpacker);

    // [4] Expiry is Unix epoch seconds and MUST be enforced locally.
    std::int64_t expiryEpochSeconds = unpacker.unpackInt<std::int64_t>();

    // [5] LeasedUntil and [6] TraceId are not required for the GPIO write.
    SkipOneMessagePackValue(unpacker);
    SkipOneMessagePackValue(unpacker);

    // Confirmation flags are typed booleans. Do not coerce strings/numbers.
    if (unpacker.getType() != MsgPack::Type::BOOL) {
        Serial.println("Rejected command with malformed RequiresConfirmation");
        return;
    }
    bool requiresConfirmation = unpacker.unpackBool();

    if (unpacker.getType() != MsgPack::Type::BOOL) {
        Serial.println("Rejected command with malformed Confirmed flag");
        return;
    }
    bool confirmed = unpacker.unpackBool();

    std::int64_t schemaVersion = unpacker.unpackInt<std::int64_t>();

    if (!unpacker.decoded()) {
        Serial.println("Rejected malformed CommandDto fields");
        return;
    }

    String error;

    if (schemaVersion != 2) {
        error = "unsupported command schema";
    } else if (tagAddress != OUTPUT_TAG_ADDRESS) {
        error = "unsupported command address";
    } else if (expiryEpochSeconds <= 0 ||
               static_cast<std::uint64_t>(expiryEpochSeconds) <=
                   CurrentUnixTimeMs() / 1000ULL) {
        error = "command expired";
    } else if (requiresConfirmation && !confirmed) {
        error = "operator confirmation required";
    } else if (!valueValid) {
        error = "do.output1 accepts only 0 or 1";
    } else if (!WriteDigitalOutput(requestedValue)) {
        error = "local output write failed";
    }

    bool success = error.length() == 0;

    Bytes result = BuildCommandResult(
        commandId,
        success,
        error,
        requestedValue);

    PersistCommandResult(commandId, result);
    PublishEncryptedQos1(commandResultTopic, result);
}

static void ProcessIncomingMqttMessage()
{
    int messageSize = mqtt.parseMessage();

    if (messageSize <= 0) {
        return;
    }

    String topic = mqtt.messageTopic();
    Bytes payload(static_cast<std::size_t>(messageSize));

    for (int index = 0; index < messageSize; ++index) {
        int byteRead = mqtt.read();
        if (byteRead < 0) {
            return;
        }

        payload[static_cast<std::size_t>(index)] =
            static_cast<std::uint8_t>(byteRead);
    }

    if (topic == authChallengeTopic) {
        AuthenticateFromChallenge(payload);
        return;
    }

    if (authenticated && topic == commandsTopic) {
        HandleCommand(payload);
    }
}


// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
// ============================================================================
//
// ArduinoMqttClient emits MQTT protocol level 4 (MQTT 3.1.1). We explicitly
// request CleanSession=true and an empty MQTT password.
//
// On every reconnect we discard the old application session key and repeat
// the challenge flow. Durable Seq and command-result cache remain intact.

unsigned long reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
unsigned long nextReconnectAttemptMs = 0;
unsigned long lastTelemetryMs = 0;

static bool SubscribeToAuthChallenge()
{
    if (!mqtt.subscribe(authChallengeTopic, 1)) {
        return false;
    }

    // subscribe() returns true for any granted QoS 0..2. SCADALGERIA Direct Firmware protocol for
    // this example is QoS1, so inspect the actual SUBACK grant as well.
    return mqtt.subscribeQoS() == 1;
}

static bool ConnectMqttAndBeginAuthentication()
{
    ClearApplicationSession();

    mqtt.setId(clientId);
    mqtt.setUsernamePassword(mqttUsername, "");
    mqtt.setCleanSession(true);
    mqtt.setKeepAliveInterval(60);
    mqtt.setConnectionTimeout(10 * 1000UL);

    Serial.printf("Connecting to %s:%u with MQTT 3.1.1...\n", mqttHost, mqttPort);

    if (!mqtt.connect(mqttHost, mqttPort)) {
        Serial.printf("MQTT connect failed, code=%d\n", mqtt.connectError());
        return false;
    }

    if (!SubscribeToAuthChallenge()) {
        Serial.println("Auth challenge subscription was not granted at QoS1");
        mqtt.stop();
        return false;
    }

    reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
    Serial.println("MQTT connected; waiting for SCADALGERIA auth challenge");
    return true;
}

static void MaintainMqttConnection()
{
    if (mqtt.connected()) {
        return;
    }

    // Never continue encrypting with a key from a dead MQTT connection.
    ClearApplicationSession();

    if (WiFi.status() != WL_CONNECTED) {
        return;
    }

    unsigned long now = millis();
    if (static_cast<long>(now - nextReconnectAttemptMs) < 0) {
        return;
    }

    if (ConnectMqttAndBeginAuthentication()) {
        nextReconnectAttemptMs = 0;
        return;
    }

    nextReconnectAttemptMs = now + reconnectDelayMs;
    reconnectDelayMs = std::min(
        reconnectDelayMs * 2,
        MAX_RECONNECT_DELAY_MS);
}

void setup()
{
    Serial.begin(115200);

    InitializeDigitalIo();
    LoadScadalgeriaProvisioning();
    LoadDurableState();

    // The surrounding application should own Wi-Fi provisioning. This snippet
    // fails closed if connectivity is not already established.
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Wi-Fi must be connected before SCADALGERIA starts");
        abort();
    }

    // The outer encrypted envelope timestamp is part of platform replay/clock
    // validation. Do not publish with an unsynchronized device clock.
    configTime(0, 0, "pool.ntp.org");

    while (time(nullptr) < 1700000000) {
        delay(100);
    }

    ConnectMqttAndBeginAuthentication();
}

void loop()
{
    MaintainMqttConnection();

    if (!mqtt.connected()) {
        delay(10);
        return;
    }

    ProcessIncomingMqttMessage();

    unsigned long now = millis();
    if (authenticated && now - lastTelemetryMs >= TELEMETRY_INTERVAL_MS) {
        lastTelemetryMs = now;
        PublishTelemetry();
    }

    // Keep the loop responsive so MQTT keepalive and incoming command traffic
    // are serviced. In production, use the copied configuration telemetryPolicy rather
    // than treating this fixed 1-second example cadence as a platform limit.
    delay(2);
}
