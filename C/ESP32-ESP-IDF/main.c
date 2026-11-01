/*
 * SCADALGERIA Direct Firmware example — C / ESP32 / ESP-IDF 6.1
 *
 * This file is intentionally a readable protocol snippet, not a complete
 * ESP-IDF application. The surrounding firmware is expected to provide:
 *
 *   - Wi-Fi/Ethernet connectivity
 *   - UTC/SNTP synchronization
 *   - secure provisioning of the copied SCADALGERIA connection configuration
 *   - production watchdog / OTA / device-health policy
 *
 * Demonstrated device behavior:
 *
 *   GPIO4 (active-low digital input)
 *       -> "di.input1" telemetry
 *       -> SCADALGERIA platform
 *       -> "do.output1" command
 *       -> GPIO18 digital output
 *       -> encrypted command result
 *
 * IMPORTANT:
 *   SCADALGERIA's current Direct Firmware endpoint MQTT listener is MQTT 3.1.1 on TCP/1883.
 *   The API-key token is NOT the MQTT password. It is used only by the
 *   HMAC/HKDF application protocol described below.
 */

// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
// ============================================================================
//
// Place Connection → Copy firmware configuration → Copy JSON at
// `/spiffs/scadalgeria-connection.json`.
// Store the API-key secret separately in NVS namespace `scada_secret`, key
// `api_key`. This keeps the reusable JSON non-secret.

#define CONNECTION_CONFIG_FILE "/spiffs/scadalgeria-connection.json"
#define INPUT_TAG_ADDRESS  "di.input1"
#define OUTPUT_TAG_ADDRESS "do.output1"
#define INPUT_GPIO  GPIO_NUM_4
#define OUTPUT_GPIO GPIO_NUM_18
#define TELEMETRY_INTERVAL_MS 1000U
#define MAX_MQTT_PAYLOAD_BYTES 4096U

static const char *TAG = "scada-example";
static char mqtt_host[256];
static int mqtt_port;
static char client_id[32];
static char mqtt_username[384];
static char key_id[64];
static char api_token[512];
static char auth_challenge_topic[512];
static char auth_response_topic[512];
static char telemetry_topic[512];
static char commands_topic[512];
static char command_result_topic[512];

static char *read_text_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) return NULL;
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    if (size <= 0) { fclose(file); return NULL; }
    char *text = calloc((size_t)size + 1, 1);
    if (text == NULL) { fclose(file); return NULL; }
    if (fread(text, 1, (size_t)size, file) != (size_t)size) { free(text); fclose(file); return NULL; }
    fclose(file);
    return text;
}

static cJSON *required_object(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsObject(value)) { ESP_LOGE(TAG, "Invalid copied configuration object: %s", name); abort(); }
    return value;
}

static const char *required_string(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsString(value) || value->valuestring == NULL || value->valuestring[0] == '\0') { ESP_LOGE(TAG, "Invalid copied configuration string: %s", name); abort(); }
    return value->valuestring;
}

static int required_int(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsNumber(value)) abort();
    return value->valueint;
}

static void copy_string(char *destination, size_t capacity, const char *value)
{
    if (strlen(value) + 1 > capacity) abort();
    strlcpy(destination, value, capacity);
}

static void create_unique_client_id(void)
{
    uint8_t random[8];
    static const char hex[] = "0123456789abcdef";
    esp_fill_random(random, sizeof(random));
    memcpy(client_id, "scada-", 6);
    for (size_t i = 0; i < sizeof(random); ++i) {
        client_id[6 + i * 2] = hex[(random[i] >> 4) & 0x0F];
        client_id[7 + i * 2] = hex[random[i] & 0x0F];
    }
    client_id[22] = '\0';
}

static void resolve_client_topic(const char *template_value, char *output, size_t capacity)
{
    const char *marker = strstr(template_value, "{clientId}");
    if (marker == NULL || strstr(marker + 10, "{clientId}") != NULL) abort();
    size_t prefix = (size_t)(marker - template_value);
    int written = snprintf(output, capacity, "%.*s%s%s", (int)prefix, template_value, client_id, marker + 10);
    if (written < 0 || (size_t)written >= capacity) abort();
}

static void require_boolean_tag(cJSON *root, const char *address, const char *direction)
{
    cJSON *tags = cJSON_GetObjectItemCaseSensitive(root, "tags");
    if (!cJSON_IsArray(tags)) abort();
    int matches = 0;
    cJSON *tag = NULL;
    cJSON_ArrayForEach(tag, tags) {
        if (strcmp(required_string(tag, "address"), address) == 0) {
            ++matches;
            if (strcmp(required_string(tag, "dataType"), "Boolean") != 0 || strcmp(required_string(tag, "direction"), direction) != 0) abort();
        }
    }
    if (matches != 1) abort();
}

static void load_api_key_secret(void)
{
    nvs_handle_t handle;
    ESP_ERROR_CHECK(nvs_open("scada_secret", NVS_READONLY, &handle));
    size_t length = sizeof(api_token);
    ESP_ERROR_CHECK(nvs_get_str(handle, "api_key", api_token, &length));
    nvs_close(handle);
    if (length < 2 || length > sizeof(api_token)) abort();
}

static void load_scadalgeria_provisioning(void)
{
    esp_vfs_spiffs_conf_t spiffs = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 4,
        .format_if_mount_failed = false,
    };
    esp_err_t mount_result = esp_vfs_spiffs_register(&spiffs);
    if (mount_result != ESP_OK && mount_result != ESP_ERR_INVALID_STATE) ESP_ERROR_CHECK(mount_result);

    char *json_text = read_text_file(CONNECTION_CONFIG_FILE);
    if (json_text == NULL) abort();
    cJSON *root = cJSON_Parse(json_text);
    free(json_text);
    if (root == NULL) abort();

    if (strcmp(required_string(root, "schema"), "scadalgeria.direct-firmware.connection") != 0 || required_int(root, "schemaVersion") != 1) abort();
    cJSON *connection = required_object(root, "connection");
    cJSON *identity = required_object(root, "identity");
    cJSON *mqtt = required_object(root, "mqtt");
    cJSON *broker = required_object(mqtt, "broker");
    cJSON *topics = required_object(mqtt, "topics");
    cJSON *qos = required_object(mqtt, "qos");
    cJSON *authentication = required_object(root, "authentication");
    cJSON *encryption = required_object(root, "encryption");
    cJSON *kdf = required_object(encryption, "sessionKeyDerivation");
    cJSON *secrets = required_object(root, "secrets");

    if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(connection, "enabled"))) abort();
    if (strcmp(required_string(mqtt, "protocol"), "3.1.1") != 0 || !cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(mqtt, "cleanSession"))) abort();
    if (strcmp(required_string(broker, "transport"), "tcp") != 0) abort();
    if (strcmp(required_string(mqtt, "clientIdRequirement"), "unique-per-active-session") != 0) abort();
    if (required_int(qos, "telemetry") != 1 || required_int(qos, "commands") != 1 || required_int(qos, "commandResults") != 1) abort();
    if (strcmp(required_string(authentication, "scheme"), "HMAC-SHA256") != 0 || strcmp(required_string(encryption, "scheme"), "AES-256-GCM") != 0) abort();
    if (strcmp(required_string(kdf, "algorithm"), "HKDF-SHA256") != 0 || strcmp(required_string(kdf, "info"), "SCADA-ENC-v1") != 0) abort();
    if (!cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(secrets, "apiKeySecretIncluded"))) abort();

    require_boolean_tag(root, INPUT_TAG_ADDRESS, "Input");
    require_boolean_tag(root, OUTPUT_TAG_ADDRESS, "Output");
    create_unique_client_id();
    copy_string(mqtt_host, sizeof(mqtt_host), required_string(broker, "host"));
    mqtt_port = required_int(broker, "port");
    copy_string(mqtt_username, sizeof(mqtt_username), required_string(mqtt, "username"));
    copy_string(key_id, sizeof(key_id), required_string(identity, "keyId"));
    resolve_client_topic(required_string(topics, "authenticationChallenge"), auth_challenge_topic, sizeof(auth_challenge_topic));
    resolve_client_topic(required_string(topics, "authenticationResponse"), auth_response_topic, sizeof(auth_response_topic));
    copy_string(telemetry_topic, sizeof(telemetry_topic), required_string(topics, "telemetry"));
    copy_string(commands_topic, sizeof(commands_topic), required_string(topics, "commands"));
    copy_string(command_result_topic, sizeof(command_result_topic), required_string(topics, "commandResults"));
    load_api_key_secret();
    cJSON_Delete(root);
}


// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
// ============================================================================
//
// Example wiring:
//   GPIO4  -> dry-contact / push-button to GND, using the ESP32 pull-up.
//   GPIO18 -> LED / logic-level isolated interface.
//
// Never connect industrial field voltage, relay coils, contactors, motors, or
// other inductive loads directly to ESP32 GPIO.

static void initialize_digital_io(void)
{
    gpio_config_t input_config = {
        .pin_bit_mask = 1ULL << INPUT_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    gpio_config_t output_config = {
        .pin_bit_mask = 1ULL << OUTPUT_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    ESP_ERROR_CHECK(gpio_config(&input_config));
    ESP_ERROR_CHECK(gpio_config(&output_config));

    // Fail-safe example state: output starts OFF.
    ESP_ERROR_CHECK(gpio_set_level(OUTPUT_GPIO, 0));
}

static int read_digital_input(void)
{
    // The input is active-low because GPIO4 uses INPUT_PULLUP.
    return gpio_get_level(INPUT_GPIO) == 0 ? 1 : 0;
}

static esp_err_t write_digital_output(int value)
{
    if (value != 0 && value != 1) {
        return ESP_ERR_INVALID_ARG;
    }

    return gpio_set_level(OUTPUT_GPIO, value);
}


// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
// ============================================================================
//
// SCADALGERIA's device->platform envelope sequence is durable protocol state.
// It must NOT reset when MQTT reconnects or the ESP32 reboots.
//
// We also persist final CommandResultDto payloads by command Id. MQTT QoS 1
// and the command pipeline are at-least-once: a command may be delivered again.
// For this idempotent set-state example, the cached result lets us answer a
// duplicate without operating GPIO18 twice.

#define COMMAND_RESULT_CACHE_CAPACITY 16U
#define COMMAND_RESULT_MAX_BYTES      512U
#define COMMAND_ID_MAX_BYTES          128U

typedef struct {
    uint8_t *data;
    size_t length;
} byte_buffer_t;

typedef struct {
    char command_id[COMMAND_ID_MAX_BYTES + 1];
    uint16_t payload_length;
    uint8_t payload[COMMAND_RESULT_MAX_BYTES];
} command_cache_entry_t;

static nvs_handle_t state_nvs;
static uint64_t outgoing_sequence = 0;
static command_cache_entry_t command_cache[COMMAND_RESULT_CACHE_CAPACITY];
static size_t command_cache_count = 0;

static void free_byte_buffer(byte_buffer_t buffer)
{
    free(buffer.data);
}

static void initialize_durable_state(void)
{
    ESP_ERROR_CHECK(nvs_open("scada", NVS_READWRITE, &state_nvs));

    esp_err_t sequence_result =
        nvs_get_u64(state_nvs, "seq", &outgoing_sequence);

    if (sequence_result == ESP_ERR_NVS_NOT_FOUND) {
        outgoing_sequence = 0;
    } else {
        ESP_ERROR_CHECK(sequence_result);
    }

    size_t cache_bytes = sizeof(command_cache);
    esp_err_t cache_result =
        nvs_get_blob(state_nvs, "results", command_cache, &cache_bytes);

    if (cache_result == ESP_OK) {
        command_cache_count = cache_bytes / sizeof(command_cache_entry_t);

        if (command_cache_count > COMMAND_RESULT_CACHE_CAPACITY) {
            ESP_LOGE(TAG, "Persisted command-result cache is malformed");
            abort();
        }
    } else if (cache_result == ESP_ERR_NVS_NOT_FOUND) {
        command_cache_count = 0;
    } else {
        ESP_ERROR_CHECK(cache_result);
    }
}

static uint64_t reserve_next_outgoing_sequence(void)
{
    // Persist BEFORE using the value. A reboot must never cause the next
    // logical telemetry/result message to reuse a previous sequence number.
    outgoing_sequence++;

    ESP_ERROR_CHECK(nvs_set_u64(state_nvs, "seq", outgoing_sequence));
    ESP_ERROR_CHECK(nvs_commit(state_nvs));

    return outgoing_sequence;
}

static byte_buffer_t find_cached_command_result(const char *command_id)
{
    for (size_t index = 0; index < command_cache_count; index++) {
        if (strcmp(command_cache[index].command_id, command_id) == 0) {
            size_t length = command_cache[index].payload_length;
            uint8_t *copy = malloc(length);

            if (copy == NULL) {
                abort();
            }

            memcpy(copy, command_cache[index].payload, length);
            return (byte_buffer_t){ .data = copy, .length = length };
        }
    }

    return (byte_buffer_t){ 0 };
}

static void persist_command_result(
    const char *command_id,
    const uint8_t *payload,
    size_t payload_length)
{
    if (strlen(command_id) > COMMAND_ID_MAX_BYTES ||
        payload_length > COMMAND_RESULT_MAX_BYTES) {
        ESP_LOGE(TAG, "Command result is too large for the example cache");
        abort();
    }

    // A small FIFO is enough for a teaching snippet. A production controller
    // can replace this with a durable command journal sized to its risk model.
    if (command_cache_count == COMMAND_RESULT_CACHE_CAPACITY) {
        memmove(
            &command_cache[0],
            &command_cache[1],
            sizeof(command_cache) - sizeof(command_cache[0]));

        command_cache_count--;
    }

    command_cache_entry_t *entry = &command_cache[command_cache_count++];
    memset(entry, 0, sizeof(*entry));

    memcpy(entry->command_id, command_id, strlen(command_id));
    entry->payload_length = (uint16_t)payload_length;
    memcpy(entry->payload, payload, payload_length);

    ESP_ERROR_CHECK(nvs_set_blob(
        state_nvs,
        "results",
        command_cache,
        command_cache_count * sizeof(command_cache_entry_t)));

    ESP_ERROR_CHECK(nvs_commit(state_nvs));
}


// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
// ============================================================================
//
// CONNECT does not make the client application-authenticated.
//
// 1. Subscribe to the exact server-issued auth/challenge topic.
// 2. Receive [ServerNonce:bin16, ExpiresAtUnixMs:int64].
// 3. Generate ClientNonce: CSPRNG(16).
// 4. Compute HMAC-SHA256(token, ServerNonce || ClientNonce || UTF8(ClientId)).
// 5. Derive a 32-byte HKDF-SHA256 key using info "SCADA-ENC-v1".
// 6. Publish [ClientNonce:bin16, Auth:bin32] to the auth/response topic.
// 7. Subscribe to the exact command topic and require the broker to grant QoS1.
//
// That final post-auth SUBACK is the promotion proof used by this full
// bidirectional example. There is no custom application "AUTH OK" packet.

static esp_mqtt_client_handle_t mqtt_client;
static SemaphoreHandle_t session_mutex;

static uint8_t session_key[32];
static bool session_authenticated = false;

static int challenge_subscription_message_id = -1;
static int command_subscription_message_id = -1;
static bool challenge_subscription_granted = false;

static uint64_t current_unix_time_ms(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    return (uint64_t)now.tv_sec * 1000ULL +
           (uint64_t)now.tv_usec / 1000ULL;
}

static void encode_uint64_big_endian(uint8_t output[8], uint64_t value)
{
    for (int index = 7; index >= 0; index--) {
        output[index] = (uint8_t)value;
        value >>= 8;
    }
}

static void clear_mqtt_application_session(void)
{
    xSemaphoreTake(session_mutex, portMAX_DELAY);

    memset(session_key, 0, sizeof(session_key));
    session_authenticated = false;

    xSemaphoreGive(session_mutex);

    challenge_subscription_granted = false;
    challenge_subscription_message_id = -1;
    command_subscription_message_id = -1;
}

static bool is_session_authenticated(void)
{
    bool authenticated;

    xSemaphoreTake(session_mutex, portMAX_DELAY);
    authenticated = session_authenticated;
    xSemaphoreGive(session_mutex);

    return authenticated;
}

static void mark_session_authenticated(void)
{
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    session_authenticated = true;
    xSemaphoreGive(session_mutex);
}

static void store_session_key(const uint8_t derived_key[32])
{
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    memcpy(session_key, derived_key, 32);
    xSemaphoreGive(session_mutex);
}

static void copy_session_key(uint8_t destination[32])
{
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    memcpy(destination, session_key, 32);
    xSemaphoreGive(session_mutex);
}

static bool compute_authentication_proof(
    const uint8_t server_nonce[16],
    const uint8_t client_nonce[16],
    uint8_t proof[32])
{
    size_t client_id_length = strlen(client_id);
    size_t message_length = 16 + 16 + client_id_length;
    uint8_t *message = malloc(message_length);

    if (message == NULL) {
        return false;
    }

    memcpy(message, server_nonce, 16);
    memcpy(message + 16, client_nonce, 16);
    memcpy(message + 32, client_id, client_id_length);

    const mbedtls_md_info_t *sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    int result = mbedtls_md_hmac(
        sha256,
        (const uint8_t *)api_token,
        strlen(api_token),
        message,
        message_length,
        proof);

    free(message);
    return result == 0;
}

static bool derive_scadalgeria_session_key(
    const uint8_t server_nonce[16],
    const uint8_t client_nonce[16],
    uint8_t derived_key[32])
{
    uint8_t salt[32];
    memcpy(salt, server_nonce, 16);
    memcpy(salt + 16, client_nonce, 16);

    const mbedtls_md_info_t *sha256 =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    static const uint8_t hkdf_info[] = "SCADA-ENC-v1";

    return mbedtls_hkdf(
               sha256,
               salt,
               sizeof(salt),
               (const uint8_t *)api_token,
               strlen(api_token),
               hkdf_info,
               sizeof(hkdf_info) - 1,
               derived_key,
               32) == 0;
}


// ============================================================================
// STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
// ============================================================================
//
// SCADALGERIA's shared DTOs use numeric MessagePack keys. On the wire that
// means compact positional arrays. Do not replace them with JSON or maps.
//
// Outbound encrypted envelope:
//
//   [ KeyId, Nonce:bin12, Ciphertext:bin, GcmTag:bin16, Seq, TsUnixMs ]
//
// AAD is exactly:
//
//   UInt64BE(Seq) || UInt64BE(TsUnixMs)
//
// Nonce rule: fresh CSPRNG 12-byte nonce for each envelope. It is NOT the
// durable sequence number.

static byte_buffer_t copy_msgpack_sbuffer(const msgpack_sbuffer *buffer)
{
    uint8_t *copy = malloc(buffer->size);

    if (copy == NULL) {
        abort();
    }

    memcpy(copy, buffer->data, buffer->size);
    return (byte_buffer_t){ .data = copy, .length = buffer->size };
}

static void pack_msgpack_string(msgpack_packer *packer, const char *value)
{
    size_t length = strlen(value);
    msgpack_pack_str(packer, length);
    msgpack_pack_str_body(packer, value, length);
}

static void pack_msgpack_binary(
    msgpack_packer *packer,
    const uint8_t *value,
    size_t length)
{
    msgpack_pack_bin(packer, length);
    msgpack_pack_bin_body(packer, value, length);
}

static bool messagepack_object_to_string(
    msgpack_object object,
    char *destination,
    size_t destination_capacity)
{
    if (object.type != MSGPACK_OBJECT_STR ||
        object.via.str.size + 1 > destination_capacity) {
        return false;
    }

    memcpy(destination, object.via.str.ptr, object.via.str.size);
    destination[object.via.str.size] = '\0';
    return true;
}

static bool messagepack_object_to_binary(
    msgpack_object object,
    const uint8_t **data,
    size_t *length)
{
    if (object.type != MSGPACK_OBJECT_BIN) {
        return false;
    }

    *data = (const uint8_t *)object.via.bin.ptr;
    *length = object.via.bin.size;
    return true;
}

static bool messagepack_object_to_uint64(
    msgpack_object object,
    uint64_t *value)
{
    if (object.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return false;
    }

    *value = object.via.u64;
    return true;
}

static bool messagepack_object_to_output_bit(
    msgpack_object object,
    int *value)
{
    if (object.type == MSGPACK_OBJECT_BOOLEAN) {
        *value = object.via.boolean ? 1 : 0;
        return true;
    }

    if (object.type == MSGPACK_OBJECT_POSITIVE_INTEGER &&
        object.via.u64 <= 1) {
        *value = (int)object.via.u64;
        return true;
    }

    if ((object.type == MSGPACK_OBJECT_FLOAT32 ||
         object.type == MSGPACK_OBJECT_FLOAT64) &&
        (object.via.f64 == 0.0 || object.via.f64 == 1.0)) {
        *value = (int)object.via.f64;
        return true;
    }

    return false;
}

static bool aes_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext,
    size_t plaintext_length,
    const uint8_t nonce[12],
    const uint8_t aad[16],
    uint8_t *ciphertext,
    uint8_t tag[16])
{
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    int result = mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key,
        256);

    if (result == 0) {
        result = mbedtls_gcm_crypt_and_tag(
            &context,
            MBEDTLS_GCM_ENCRYPT,
            plaintext_length,
            nonce,
            12,
            aad,
            16,
            plaintext,
            ciphertext,
            16,
            tag);
    }

    mbedtls_gcm_free(&context);
    return result == 0;
}

static bool aes_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t nonce[12],
    const uint8_t aad[16],
    const uint8_t tag[16],
    uint8_t *plaintext)
{
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    int result = mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key,
        256);

    if (result == 0) {
        result = mbedtls_gcm_auth_decrypt(
            &context,
            ciphertext_length,
            nonce,
            12,
            aad,
            16,
            tag,
            16,
            ciphertext,
            plaintext);
    }

    mbedtls_gcm_free(&context);
    return result == 0;
}

static byte_buffer_t build_auth_response_payload(
    const uint8_t client_nonce[16],
    const uint8_t proof[32])
{
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    // MqttAuthResponseDto = [ ClientNonce, Auth ]
    msgpack_pack_array(&packer, 2);
    pack_msgpack_binary(&packer, client_nonce, 16);
    pack_msgpack_binary(&packer, proof, 32);

    byte_buffer_t result = copy_msgpack_sbuffer(&buffer);
    msgpack_sbuffer_destroy(&buffer);
    return result;
}

static byte_buffer_t build_telemetry_payload(int digital_input_value)
{
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    // TagFrameBatchDto = [ Frames, TraceId|null, SchemaVersion=1 ]
    msgpack_pack_array(&packer, 3);

    // Frames: one TagFrameDto.
    msgpack_pack_array(&packer, 1);

    // TagFrameDto = [ Address, ValNum, ValStr, TsUnixMs, Quality ]
    msgpack_pack_array(&packer, 5);
    pack_msgpack_string(&packer, INPUT_TAG_ADDRESS);
    msgpack_pack_double(&packer, (double)digital_input_value);
    msgpack_pack_nil(&packer);       // ValStr
    msgpack_pack_int64(&packer, 0);  // platform stamps Direct Firmware frame time.
    msgpack_pack_int(&packer, 192);  // Good quality.

    msgpack_pack_nil(&packer);       // TraceId
    msgpack_pack_int(&packer, 1);    // SchemaVersion

    byte_buffer_t result = copy_msgpack_sbuffer(&buffer);
    msgpack_sbuffer_destroy(&buffer);
    return result;
}

static byte_buffer_t build_command_result_payload(
    const char *command_id,
    bool success,
    const char *error_message,
    int applied_value)
{
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    // CommandResultDto = [ CommandId, Success, Error, Data, SchemaVersion=1 ]
    msgpack_pack_array(&packer, 5);
    pack_msgpack_string(&packer, command_id);

    if (success) {
        msgpack_pack_true(&packer);
    } else {
        msgpack_pack_false(&packer);
    }

    if (error_message != NULL) {
        pack_msgpack_string(&packer, error_message);
    } else {
        msgpack_pack_nil(&packer);
    }

    if (success) {
        char data_json[48];
        snprintf(
            data_json,
            sizeof(data_json),
            "{\"appliedValue\":%d}",
            applied_value);

        pack_msgpack_string(&packer, data_json);
    } else {
        msgpack_pack_nil(&packer);
    }

    msgpack_pack_int(&packer, 1);

    byte_buffer_t result = copy_msgpack_sbuffer(&buffer);
    msgpack_sbuffer_destroy(&buffer);
    return result;
}

static byte_buffer_t encrypt_scadalgeria_payload(byte_buffer_t plaintext)
{
    uint64_t sequence = reserve_next_outgoing_sequence();
    uint64_t timestamp_ms = current_unix_time_ms();

    uint8_t nonce[12];
    uint8_t aad[16];
    uint8_t gcm_tag[16];
    uint8_t key_snapshot[32];

    esp_fill_random(nonce, sizeof(nonce));
    encode_uint64_big_endian(aad, sequence);
    encode_uint64_big_endian(aad + 8, timestamp_ms);
    copy_session_key(key_snapshot);

    uint8_t *ciphertext = malloc(plaintext.length);
    if (ciphertext == NULL) {
        abort();
    }

    if (!aes_gcm_encrypt(
            key_snapshot,
            plaintext.data,
            plaintext.length,
            nonce,
            aad,
            ciphertext,
            gcm_tag)) {
        free(ciphertext);
        ESP_LOGE(TAG, "AES-GCM encryption failed");
        abort();
    }

    msgpack_sbuffer buffer;
    msgpack_packer packer;
    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    msgpack_pack_array(&packer, 6);
    pack_msgpack_string(&packer, key_id);
    pack_msgpack_binary(&packer, nonce, sizeof(nonce));
    pack_msgpack_binary(&packer, ciphertext, plaintext.length);
    pack_msgpack_binary(&packer, gcm_tag, sizeof(gcm_tag));
    msgpack_pack_uint64(&packer, sequence);
    msgpack_pack_uint64(&packer, timestamp_ms);

    free(ciphertext);

    byte_buffer_t envelope = copy_msgpack_sbuffer(&buffer);
    msgpack_sbuffer_destroy(&buffer);
    return envelope;
}

static bool decrypt_scadalgeria_payload(
    const uint8_t *envelope_data,
    size_t envelope_length,
    byte_buffer_t *plaintext)
{
    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    size_t offset = 0;
    bool parsed = msgpack_unpack_next(
        &unpacked,
        (const char *)envelope_data,
        envelope_length,
        &offset);

    if (!parsed ||
        unpacked.data.type != MSGPACK_OBJECT_ARRAY ||
        unpacked.data.via.array.size != 6) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    msgpack_object *fields = unpacked.data.via.array.ptr;

    char envelope_key_id[64];
    const uint8_t *nonce;
    const uint8_t *ciphertext;
    const uint8_t *gcm_tag;
    size_t nonce_length;
    size_t ciphertext_length;
    size_t gcm_tag_length;
    uint64_t sequence;
    uint64_t timestamp_ms;

    bool valid =
        messagepack_object_to_string(
            fields[0], envelope_key_id, sizeof(envelope_key_id)) &&
        strcmp(envelope_key_id, key_id) == 0 &&
        messagepack_object_to_binary(fields[1], &nonce, &nonce_length) &&
        nonce_length == 12 &&
        messagepack_object_to_binary(
            fields[2], &ciphertext, &ciphertext_length) &&
        messagepack_object_to_binary(fields[3], &gcm_tag, &gcm_tag_length) &&
        gcm_tag_length == 16 &&
        messagepack_object_to_uint64(fields[4], &sequence) &&
        messagepack_object_to_uint64(fields[5], &timestamp_ms);

    if (!valid) {
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    uint8_t aad[16];
    uint8_t key_snapshot[32];
    encode_uint64_big_endian(aad, sequence);
    encode_uint64_big_endian(aad + 8, timestamp_ms);
    copy_session_key(key_snapshot);

    uint8_t *decrypted = malloc(ciphertext_length);
    if (decrypted == NULL) {
        msgpack_unpacked_destroy(&unpacked);
        abort();
    }

    bool decrypted_ok = aes_gcm_decrypt(
        key_snapshot,
        ciphertext,
        ciphertext_length,
        nonce,
        aad,
        gcm_tag,
        decrypted);

    if (!decrypted_ok) {
        free(decrypted);
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    plaintext->data = decrypted;
    plaintext->length = ciphertext_length;

    msgpack_unpacked_destroy(&unpacked);
    return true;
}


// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
// ============================================================================

static bool publish_qos1(
    const char *topic,
    const uint8_t *payload,
    size_t payload_length)
{
    int message_id = esp_mqtt_client_publish(
        mqtt_client,
        topic,
        (const char *)payload,
        (int)payload_length,
        1,      // QoS 1
        0);     // not retained

    return message_id >= 0;
}

static bool publish_encrypted_qos1(
    const char *topic,
    byte_buffer_t plaintext)
{
    byte_buffer_t envelope = encrypt_scadalgeria_payload(plaintext);

    bool published = publish_qos1(
        topic,
        envelope.data,
        envelope.length);

    free_byte_buffer(envelope);
    return published;
}

static bool begin_scadalgeria_authentication(
    const uint8_t *challenge_payload,
    size_t challenge_length)
{
    if (!challenge_subscription_granted) {
        ESP_LOGW(TAG, "Ignoring auth challenge before SUBACK was granted");
        return false;
    }

    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    size_t offset = 0;
    bool parsed = msgpack_unpack_next(
        &unpacked,
        (const char *)challenge_payload,
        challenge_length,
        &offset);

    if (!parsed ||
        unpacked.data.type != MSGPACK_OBJECT_ARRAY ||
        unpacked.data.via.array.size != 2) {
        ESP_LOGW(TAG, "Rejected malformed SCADALGERIA auth challenge");
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    msgpack_object *fields = unpacked.data.via.array.ptr;

    const uint8_t *server_nonce;
    size_t server_nonce_length;
    uint64_t expires_at_ms;

    bool valid =
        messagepack_object_to_binary(
            fields[0], &server_nonce, &server_nonce_length) &&
        server_nonce_length == 16 &&
        messagepack_object_to_uint64(fields[1], &expires_at_ms);

    if (!valid || current_unix_time_ms() >= expires_at_ms) {
        ESP_LOGW(TAG, "Rejected invalid or expired auth challenge");
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    uint8_t client_nonce[16];
    uint8_t proof[32];
    uint8_t derived_key[32];

    esp_fill_random(client_nonce, sizeof(client_nonce));

    if (!compute_authentication_proof(server_nonce, client_nonce, proof) ||
        !derive_scadalgeria_session_key(
            server_nonce,
            client_nonce,
            derived_key)) {
        ESP_LOGE(TAG, "Could not compute SCADALGERIA auth material");
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    store_session_key(derived_key);

    byte_buffer_t auth_response =
        build_auth_response_payload(client_nonce, proof);

    bool response_published = publish_qos1(
        auth_response_topic,
        auth_response.data,
        auth_response.length);

    free_byte_buffer(auth_response);

    if (!response_published) {
        ESP_LOGW(TAG, "Auth-response publish could not be queued");
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    // Do not set session_authenticated here. A successful PUBLISH call only
    // means the MQTT library accepted the outgoing packet. We prove platform
    // promotion by subscribing to the post-auth command topic.
    command_subscription_message_id =
        esp_mqtt_client_subscribe(mqtt_client, commands_topic, 1);

    if (command_subscription_message_id < 0) {
        ESP_LOGW(TAG, "Command subscription could not be queued");
        msgpack_unpacked_destroy(&unpacked);
        return false;
    }

    msgpack_unpacked_destroy(&unpacked);
    return true;
}

static void publish_digital_input_telemetry(void)
{
    if (!is_session_authenticated()) {
        return;
    }

    int input_value = read_digital_input();
    byte_buffer_t telemetry = build_telemetry_payload(input_value);

    if (!publish_encrypted_qos1(telemetry_topic, telemetry)) {
        ESP_LOGW(TAG, "Telemetry publish could not be queued");
    }

    free_byte_buffer(telemetry);

    // A local MQTT publish/PUBACK is NOT proof of semantic acceptance.
    // The platform can still reject replay, clock, ACL, tag, type, quality, range,
    // rate-limit, or backpressure violations.
}


// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
// ============================================================================

static void handle_scadalgeria_command(
    const uint8_t *encrypted_payload,
    size_t encrypted_length)
{
    byte_buffer_t plaintext = { 0 };

    if (!decrypt_scadalgeria_payload(
            encrypted_payload,
            encrypted_length,
            &plaintext)) {
        ESP_LOGW(TAG, "Rejected command envelope: key/shape/GCM validation failed");
        return;
    }

    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    size_t offset = 0;
    bool parsed = msgpack_unpack_next(
        &unpacked,
        (const char *)plaintext.data,
        plaintext.length,
        &offset);

    if (!parsed ||
        unpacked.data.type != MSGPACK_OBJECT_ARRAY ||
        unpacked.data.via.array.size != 10) {
        ESP_LOGW(TAG, "Rejected malformed CommandDto");
        msgpack_unpacked_destroy(&unpacked);
        free_byte_buffer(plaintext);
        return;
    }

    msgpack_object *fields = unpacked.data.via.array.ptr;

    char command_id[COMMAND_ID_MAX_BYTES + 1];
    char tag_address[129];
    uint64_t expiry_epoch_seconds;
    uint64_t schema_version;

    bool header_valid =
        messagepack_object_to_string(
            fields[0], command_id, sizeof(command_id)) &&
        command_id[0] != '\0' &&
        messagepack_object_to_string(
            fields[1], tag_address, sizeof(tag_address)) &&
        messagepack_object_to_uint64(fields[4], &expiry_epoch_seconds) &&
        messagepack_object_to_uint64(fields[9], &schema_version);

    if (!header_valid) {
        ESP_LOGW(TAG, "Rejected CommandDto with invalid identity/expiry/schema fields");
        msgpack_unpacked_destroy(&unpacked);
        free_byte_buffer(plaintext);
        return;
    }

    // At-least-once delivery: answer a duplicate from durable state without
    // applying GPIO18 again.
    byte_buffer_t cached_result = find_cached_command_result(command_id);

    if (cached_result.data != NULL) {
        publish_encrypted_qos1(command_result_topic, cached_result);
        free_byte_buffer(cached_result);

        msgpack_unpacked_destroy(&unpacked);
        free_byte_buffer(plaintext);
        return;
    }

    const char *error_message = NULL;
    int requested_output_value = 0;

    bool requires_confirmation_is_bool =
        fields[7].type == MSGPACK_OBJECT_BOOLEAN;

    bool confirmed_is_bool =
        fields[8].type == MSGPACK_OBJECT_BOOLEAN;

    bool output_value_valid =
        messagepack_object_to_output_bit(
            fields[2],
            &requested_output_value);

    if (schema_version != 2) {
        error_message = "unsupported command schema";
    } else if (strcmp(tag_address, OUTPUT_TAG_ADDRESS) != 0) {
        error_message = "unsupported command address";
    } else if (expiry_epoch_seconds <= current_unix_time_ms() / 1000ULL) {
        error_message = "command expired";
    } else if (!requires_confirmation_is_bool || !confirmed_is_bool) {
        error_message = "invalid confirmation flags";
    } else if (fields[7].via.boolean && !fields[8].via.boolean) {
        error_message = "operator confirmation required";
    } else if (!output_value_valid) {
        error_message = "do.output1 accepts only 0 or 1";
    } else if (write_digital_output(requested_output_value) != ESP_OK) {
        error_message = "local output write failed";
    }

    bool success = error_message == NULL;

    byte_buffer_t result = build_command_result_payload(
        command_id,
        success,
        error_message,
        requested_output_value);

    // Persist the final result before publishing it. A QoS1 redelivery after
    // a reboot can then be answered without repeating this idempotent action.
    persist_command_result(command_id, result.data, result.length);

    if (!publish_encrypted_qos1(command_result_topic, result)) {
        ESP_LOGW(TAG, "Command result publish could not be queued");
    }

    free_byte_buffer(result);
    msgpack_unpacked_destroy(&unpacked);
    free_byte_buffer(plaintext);
}


// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
// ============================================================================
//
// SCADALGERIA requires:
//   - MQTT 3.1.1
//   - CleanSession=true
//   - exact source-bound topics
//   - no command subscription before application authentication
//
// Every MQTT reconnect starts a NEW SCADALGERIA application session:
// discard the old session key, subscribe only to auth/challenge, and wait for
// the new challenge. Durable sequence/cache state is intentionally retained.

static uint8_t incoming_payload[MAX_MQTT_PAYLOAD_BYTES];
static int incoming_total_length = 0;
static int incoming_received_length = 0;
static char incoming_topic[512];

static bool mqtt_topic_matches(
    const char *topic,
    int topic_length,
    const char *expected)
{
    size_t expected_length = strlen(expected);

    return topic_length == (int)expected_length &&
           memcmp(topic, expected, expected_length) == 0;
}

static bool subscription_event_granted_qos1(esp_mqtt_event_handle_t event)
{
    // ESP-MQTT exposes MQTT 3.1.1 SUBACK return codes through event->data.
    // A successful event alone is not enough: 0x80 means the broker refused.
    return event->error_handle != NULL &&
           event->error_handle->error_type == MQTT_ERROR_TYPE_NONE &&
           event->data_len == 1 &&
           (uint8_t)event->data[0] == 0x01;
}

static void handle_complete_mqtt_publish(void)
{
    if (strcmp(incoming_topic, auth_challenge_topic) == 0) {
        begin_scadalgeria_authentication(
            incoming_payload,
            (size_t)incoming_total_length);
        return;
    }

    if (strcmp(incoming_topic, commands_topic) == 0 &&
        is_session_authenticated()) {
        handle_scadalgeria_command(
            incoming_payload,
            (size_t)incoming_total_length);
    }
}

static void mqtt_event_handler(
    void *handler_args,
    esp_event_base_t base,
    int32_t event_id,
    void *event_data)
{
    (void)handler_args;
    (void)base;

    esp_mqtt_event_handle_t event = event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT transport connected; starting SCADALGERIA auth");

            clear_mqtt_application_session();

            challenge_subscription_message_id =
                esp_mqtt_client_subscribe(
                    mqtt_client,
                    auth_challenge_topic,
                    1);

            if (challenge_subscription_message_id < 0) {
                ESP_LOGE(TAG, "Could not subscribe to auth challenge topic");
            }
            break;

        case MQTT_EVENT_SUBSCRIBED:
            if (event->msg_id == challenge_subscription_message_id) {
                if (!subscription_event_granted_qos1(event)) {
                    ESP_LOGE(TAG, "Auth challenge subscription was not granted at QoS1");
                    clear_mqtt_application_session();
                    break;
                }

                challenge_subscription_granted = true;
                ESP_LOGI(TAG, "Auth challenge subscription granted");
                break;
            }

            if (event->msg_id == command_subscription_message_id) {
                if (!subscription_event_granted_qos1(event)) {
                    ESP_LOGE(TAG, "Post-auth command subscription was not granted at QoS1");
                    clear_mqtt_application_session();
                    break;
                }

                mark_session_authenticated();
                ESP_LOGI(TAG, "SCADALGERIA application session authenticated");
            }
            break;

        case MQTT_EVENT_DATA: {
            if (event->current_data_offset == 0) {
                incoming_total_length = event->total_data_len;
                incoming_received_length = 0;

                if (incoming_total_length <= 0 ||
                    incoming_total_length > (int)sizeof(incoming_payload)) {
                    ESP_LOGW(TAG, "Incoming MQTT payload exceeds example buffer");
                    incoming_total_length = 0;
                    break;
                }

                if (event->topic_len <= 0 ||
                    event->topic_len >= (int)sizeof(incoming_topic)) {
                    ESP_LOGW(TAG, "Incoming MQTT topic is invalid/too long");
                    incoming_total_length = 0;
                    break;
                }

                memcpy(incoming_topic, event->topic, event->topic_len);
                incoming_topic[event->topic_len] = '\0';
            }

            if (incoming_total_length == 0 ||
                event->current_data_offset < 0 ||
                event->data_len < 0 ||
                event->current_data_offset + event->data_len > incoming_total_length) {
                break;
            }

            memcpy(
                incoming_payload + event->current_data_offset,
                event->data,
                event->data_len);

            int end_offset = event->current_data_offset + event->data_len;
            if (end_offset > incoming_received_length) {
                incoming_received_length = end_offset;
            }

            if (incoming_received_length == incoming_total_length) {
                handle_complete_mqtt_publish();
                incoming_total_length = 0;
                incoming_received_length = 0;
            }
            break;
        }

        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "MQTT disconnected; old SCADALGERIA session discarded");
            clear_mqtt_application_session();
            break;

        case MQTT_EVENT_ERROR:
            ESP_LOGW(TAG, "MQTT error; application session will be re-authenticated");
            clear_mqtt_application_session();
            break;

        default:
            break;
    }
}

static void telemetry_task(void *argument)
{
    (void)argument;

    for (;;) {
        if (is_session_authenticated()) {
            publish_digital_input_telemetry();
        }

        // This one-second cadence is only illustrative. Production firmware
        // must obey the server-issued the copied configuration telemetryPolicy rather
        // than hardcoding an aggressive rate or dumping an offline backlog.
        vTaskDelay(pdMS_TO_TICKS(TELEMETRY_INTERVAL_MS));
    }
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());

    load_scadalgeria_provisioning();
    initialize_durable_state();
    initialize_digital_io();

    session_mutex = xSemaphoreCreateMutex();
    if (session_mutex == NULL) {
        abort();
    }

    // Surrounding firmware should already have network connectivity and a
    // sane UTC clock before this point. The outer AES-GCM envelope timestamp
    // participates in platform replay/clock validation.

    esp_mqtt_client_config_t mqtt_config = {
        .broker.address.hostname = mqtt_host,
        .broker.address.port = mqtt_port,
        .broker.address.transport = MQTT_TRANSPORT_OVER_TCP,

        .credentials.client_id = client_id,
        .credentials.username = mqtt_username,
        .credentials.authentication.password = "",

        // MQTT 3.1.1 + CleanSession=true.
        .session.protocol_ver = MQTT_PROTOCOL_V_3_1_1,
        .session.disable_clean_session = false,
    };

    mqtt_client = esp_mqtt_client_init(&mqtt_config);
    if (mqtt_client == NULL) {
        abort();
    }

    ESP_ERROR_CHECK(esp_mqtt_client_register_event(
        mqtt_client,
        ESP_EVENT_ANY_ID,
        mqtt_event_handler,
        NULL));

    ESP_ERROR_CHECK(esp_mqtt_client_start(mqtt_client));

    xTaskCreate(
        telemetry_task,
        "scada_telemetry",
        6144,
        NULL,
        5,
        NULL);

    // app_main may return; ESP-MQTT and telemetry_task continue running.
}
