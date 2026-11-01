/*
 * SCADALGERIA Direct Firmware example — Raspberry Pi 5 / C
 *
 * Complete Direct Firmware flow:
 *
 *     BCM17 -> "di.input1" telemetry -> SCADALGERIA
 *     BCM27 <- "do.output1" command  <- SCADALGERIA
 *
 * This file is intentionally a readable integration snippet. It uses ordinary
 * Paho MQTT C, msgpack-c, OpenSSL and libgpiod APIs and defines the small
 * SCADALGERIA-specific helpers explicitly.
 */


/* ========================================================================== */
/* STEP 1 OF 9 — IMPORTS AND TARGET NOTES */
/* ========================================================================== */

#include <MQTTClient.h>
#include <gpiod.h>
#include <msgpack.h>
#include <cjson/cJSON.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


/* ========================================================================== */
/* ========================================================================== */
/* STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET */
/*                                                                            */
/* Save Connection → Copy firmware configuration → Copy JSON as              */
/* `scadalgeria-connection.json`. Supply SCADALGERIA_API_KEY separately.      */
/* ========================================================================== */

typedef struct
{
    const char *host;
    int port;
    const char *client_id;
    const char *mqtt_username;
    const char *api_key_id;
    const char *api_key_token;
    const char *auth_challenge_topic;
    const char *auth_response_topic;
    const char *telemetry_topic;
    const char *commands_topic;
    const char *command_result_topic;
    const char *gpio_chip;
} scada_configuration_t;

static cJSON *connection_manifest = NULL;
static scada_configuration_t configuration;
static char generated_client_id[32];
static char auth_challenge_topic[512];
static char auth_response_topic[512];

static const char *required_secret(const char *name)
{
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        fprintf(stderr, "Missing required secret: %s\n", name);
        exit(2);
    }
    return value;
}

static const char *environment_value_or(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value != NULL && value[0] != '\0' ? value : fallback;
}

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
    if (!cJSON_IsObject(value)) { fprintf(stderr, "Invalid copied configuration object: %s\n", name); exit(2); }
    return value;
}

static const char *required_string(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsString(value) || value->valuestring == NULL || value->valuestring[0] == '\0') {
        fprintf(stderr, "Invalid copied configuration string: %s\n", name); exit(2);
    }
    return value->valuestring;
}

static int required_int(cJSON *parent, const char *name)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(parent, name);
    if (!cJSON_IsNumber(value)) { fprintf(stderr, "Invalid copied configuration number: %s\n", name); exit(2); }
    return value->valueint;
}

static void require_boolean_tag(cJSON *manifest, const char *address, const char *direction)
{
    cJSON *tags = cJSON_GetObjectItemCaseSensitive(manifest, "tags");
    if (!cJSON_IsArray(tags)) { fprintf(stderr, "Copied configuration has no tags array\n"); exit(2); }
    int matches = 0;
    cJSON *tag = NULL;
    cJSON_ArrayForEach(tag, tags) {
        if (strcmp(required_string(tag, "address"), address) == 0) {
            ++matches;
            if (strcmp(required_string(tag, "dataType"), "Boolean") != 0 || strcmp(required_string(tag, "direction"), direction) != 0) {
                fprintf(stderr, "Tag %s must be Boolean/%s\n", address, direction); exit(2);
            }
        }
    }
    if (matches != 1) { fprintf(stderr, "Copied configuration must contain exactly one tag %s\n", address); exit(2); }
}

static void create_unique_client_id(void)
{
    unsigned char random[8];
    static const char hex[] = "0123456789abcdef";
    if (RAND_bytes(random, sizeof(random)) != 1) { fprintf(stderr, "RAND_bytes failed\n"); exit(2); }
    memcpy(generated_client_id, "scada-", 6);
    for (size_t i = 0; i < sizeof(random); ++i) {
        generated_client_id[6 + i * 2] = hex[(random[i] >> 4) & 0x0F];
        generated_client_id[7 + i * 2] = hex[random[i] & 0x0F];
    }
    generated_client_id[22] = '\0';
}

static void resolve_client_topic(const char *template_value, const char *client_id, char *output, size_t capacity)
{
    const char *marker = strstr(template_value, "{clientId}");
    if (marker == NULL || strstr(marker + 10, "{clientId}") != NULL) { fprintf(stderr, "Invalid authentication topic template\n"); exit(2); }
    size_t prefix = (size_t)(marker - template_value);
    int written = snprintf(output, capacity, "%.*s%s%s", (int)prefix, template_value, client_id, marker + 10);
    if (written < 0 || (size_t)written >= capacity) { fprintf(stderr, "Resolved topic too long\n"); exit(2); }
}

static void load_configuration(void)
{
    const char *path = environment_value_or("SCADALGERIA_CONFIG_FILE", "scadalgeria-connection.json");
    char *json_text = read_text_file(path);
    if (json_text == NULL) { fprintf(stderr, "Unable to read copied connection configuration: %s\n", path); exit(2); }
    connection_manifest = cJSON_Parse(json_text);
    free(json_text);
    if (connection_manifest == NULL) { fprintf(stderr, "Copied connection configuration is not valid JSON\n"); exit(2); }

    if (strcmp(required_string(connection_manifest, "schema"), "scadalgeria.direct-firmware.connection") != 0 || required_int(connection_manifest, "schemaVersion") != 1) { fprintf(stderr, "Unsupported connection configuration schema\n"); exit(2); }

    cJSON *connection = required_object(connection_manifest, "connection");
    cJSON *identity = required_object(connection_manifest, "identity");
    cJSON *mqtt = required_object(connection_manifest, "mqtt");
    cJSON *broker = required_object(mqtt, "broker");
    cJSON *topics = required_object(mqtt, "topics");
    cJSON *qos = required_object(mqtt, "qos");
    cJSON *authentication = required_object(connection_manifest, "authentication");
    cJSON *encryption = required_object(connection_manifest, "encryption");
    cJSON *kdf = required_object(encryption, "sessionKeyDerivation");
    cJSON *secrets = required_object(connection_manifest, "secrets");

    cJSON *enabled = cJSON_GetObjectItemCaseSensitive(connection, "enabled");
    cJSON *clean_session = cJSON_GetObjectItemCaseSensitive(mqtt, "cleanSession");
    cJSON *secret_included = cJSON_GetObjectItemCaseSensitive(secrets, "apiKeySecretIncluded");
    if (!cJSON_IsTrue(enabled)) { fprintf(stderr, "The copied Connection is disabled\n"); exit(2); }
    if (strcmp(required_string(mqtt, "protocol"), "3.1.1") != 0 || !cJSON_IsTrue(clean_session)) { fprintf(stderr, "MQTT 3.1.1 with cleanSession=true is required\n"); exit(2); }
    if (strcmp(required_string(broker, "transport"), "tcp") != 0) { fprintf(stderr, "Unsupported copied MQTT transport\n"); exit(2); }
    if (strcmp(required_string(mqtt, "clientIdRequirement"), "unique-per-active-session") != 0) { fprintf(stderr, "Unsupported clientIdRequirement\n"); exit(2); }
    if (required_int(qos, "telemetry") != 1 || required_int(qos, "commands") != 1 || required_int(qos, "commandResults") != 1) { fprintf(stderr, "Copied telemetry/command/result QoS must be 1\n"); exit(2); }
    if (strcmp(required_string(authentication, "scheme"), "HMAC-SHA256") != 0 || strcmp(required_string(encryption, "scheme"), "AES-256-GCM") != 0) { fprintf(stderr, "Unsupported authentication/encryption contract\n"); exit(2); }
    if (strcmp(required_string(kdf, "algorithm"), "HKDF-SHA256") != 0 || strcmp(required_string(kdf, "info"), "SCADA-ENC-v1") != 0) { fprintf(stderr, "Unsupported session-key derivation contract\n"); exit(2); }
    if (!cJSON_IsFalse(secret_included)) { fprintf(stderr, "Connection Copy JSON must not contain the API-key secret\n"); exit(2); }

    require_boolean_tag(connection_manifest, "di.input1", "Input");
    require_boolean_tag(connection_manifest, "do.output1", "Output");
    create_unique_client_id();

    configuration.host = required_string(broker, "host");
    configuration.port = required_int(broker, "port");
    configuration.client_id = generated_client_id;
    configuration.mqtt_username = required_string(mqtt, "username");
    configuration.api_key_id = required_string(identity, "keyId");
    configuration.api_key_token = required_secret("SCADALGERIA_API_KEY");
    resolve_client_topic(required_string(topics, "authenticationChallenge"), generated_client_id, auth_challenge_topic, sizeof(auth_challenge_topic));
    resolve_client_topic(required_string(topics, "authenticationResponse"), generated_client_id, auth_response_topic, sizeof(auth_response_topic));
    configuration.auth_challenge_topic = auth_challenge_topic;
    configuration.auth_response_topic = auth_response_topic;
    configuration.telemetry_topic = required_string(topics, "telemetry");
    configuration.commands_topic = required_string(topics, "commands");
    configuration.command_result_topic = required_string(topics, "commandResults");
    configuration.gpio_chip = environment_value_or("SCADALGERIA_GPIO_CHIP", "/dev/gpiochip0");
}

#define INPUT_TAG_ADDRESS  "di.input1"
#define OUTPUT_TAG_ADDRESS "do.output1"
#define MQTT_QOS 1

typedef struct { uint8_t *data; size_t length; } byte_buffer_t;
static void free_byte_buffer(byte_buffer_t buffer) { free(buffer.data); }

/* ========================================================================== */
/*
/* STEP 3 OF 9 — LOCAL DIGITAL I/O */
/*                                                                            */
/* BCM17: active-low switch input with pull-up.                               */
/* BCM27: set-state digital output.                                           */
/*                                                                            */
/* Never connect industrial loads directly to Raspberry Pi GPIO.              */
/* ========================================================================== */

typedef struct
{
    struct gpiod_chip *chip;
    struct gpiod_line_request *request;
} digital_io_t;

static digital_io_t digital_io;

static void initialize_digital_io(void)
{
    const unsigned int input_offset = 17;
    const unsigned int output_offset = 27;

    struct gpiod_line_settings *input_settings =
        gpiod_line_settings_new();

    struct gpiod_line_settings *output_settings =
        gpiod_line_settings_new();

    struct gpiod_line_config *line_config =
        gpiod_line_config_new();

    struct gpiod_request_config *request_config =
        gpiod_request_config_new();

    if (
        input_settings == NULL
        || output_settings == NULL
        || line_config == NULL
        || request_config == NULL
    )
    {
        fprintf(stderr, "Unable to allocate libgpiod configuration\n");
        exit(2);
    }

    gpiod_line_settings_set_direction(
        input_settings,
        GPIOD_LINE_DIRECTION_INPUT
    );

    gpiod_line_settings_set_bias(
        input_settings,
        GPIOD_LINE_BIAS_PULL_UP
    );

    gpiod_line_settings_set_direction(
        output_settings,
        GPIOD_LINE_DIRECTION_OUTPUT
    );

    gpiod_line_settings_set_output_value(
        output_settings,
        GPIOD_LINE_VALUE_INACTIVE
    );

    if (
        gpiod_line_config_add_line_settings(
            line_config,
            &input_offset,
            1,
            input_settings
        ) < 0
        || gpiod_line_config_add_line_settings(
            line_config,
            &output_offset,
            1,
            output_settings
        ) < 0
    )
    {
        fprintf(stderr, "Unable to configure GPIO lines\n");
        exit(2);
    }

    gpiod_request_config_set_consumer(
        request_config,
        "scadalgeria-example"
    );

    digital_io.chip = gpiod_chip_open(
        configuration.gpio_chip
    );

    if (digital_io.chip == NULL)
    {
        perror("gpiod_chip_open");
        exit(2);
    }

    digital_io.request = gpiod_chip_request_lines(
        digital_io.chip,
        request_config,
        line_config
    );

    gpiod_request_config_free(request_config);
    gpiod_line_config_free(line_config);
    gpiod_line_settings_free(input_settings);
    gpiod_line_settings_free(output_settings);

    if (digital_io.request == NULL)
    {
        perror("gpiod_chip_request_lines");
        exit(2);
    }
}

static int read_digital_input(void)
{
    enum gpiod_line_value raw_value =
        gpiod_line_request_get_value(
            digital_io.request,
            17
        );

    if (raw_value < 0)
    {
        perror("gpiod_line_request_get_value");
        exit(2);
    }

    return raw_value == GPIOD_LINE_VALUE_INACTIVE
        ? 1
        : 0;
}

static void write_digital_output(int value)
{
    enum gpiod_line_value line_value = value == 1
        ? GPIOD_LINE_VALUE_ACTIVE
        : GPIOD_LINE_VALUE_INACTIVE;

    if (
        gpiod_line_request_set_value(
            digital_io.request,
            27,
            line_value
        ) < 0
    )
    {
        perror("gpiod_line_request_set_value");
        exit(2);
    }
}


/* ========================================================================== */
/* STEP 4 OF 9 — DURABLE DEVICE STATE */
/*                                                                            */
/* Seq survives reconnects/restarts. The incremented value is persisted       */
/* before it is used. Final command results are cached by CommandDto.Id.       */
/* ========================================================================== */

#define MAX_CACHED_RESULTS 64
#define MAX_COMMAND_ID     128
#define MAX_RESULT_BYTES   512

typedef struct
{
    char command_id[MAX_COMMAND_ID + 1];
    uint16_t payload_length;
    uint8_t payload[MAX_RESULT_BYTES];
} command_cache_entry_t;

static uint64_t outgoing_sequence = 0;
static command_cache_entry_t command_cache[MAX_CACHED_RESULTS];
static size_t command_cache_count = 0;

static void atomic_write_file(
    const char *path,
    const void *data,
    size_t length
)
{
    char temporary_path[256];

    snprintf(
        temporary_path,
        sizeof temporary_path,
        "%s.tmp",
        path
    );

    FILE *file = fopen(
        temporary_path,
        "wb"
    );

    if (file == NULL)
    {
        perror("fopen state temp");
        exit(2);
    }

    if (fwrite(data, 1, length, file) != length)
    {
        perror("fwrite state");
        fclose(file);
        exit(2);
    }

    fflush(file);
    fclose(file);

    if (rename(temporary_path, path) != 0)
    {
        perror("rename state");
        exit(2);
    }
}

static void load_device_state(void)
{
    FILE *sequence_file = fopen(
        ".scadalgeria-seq",
        "rb"
    );

    if (sequence_file != NULL)
    {
        (void)fread(
            &outgoing_sequence,
            sizeof outgoing_sequence,
            1,
            sequence_file
        );

        fclose(sequence_file);
    }

    FILE *results_file = fopen(
        ".scadalgeria-results",
        "rb"
    );

    if (results_file != NULL)
    {
        command_cache_count = fread(
            command_cache,
            sizeof command_cache[0],
            MAX_CACHED_RESULTS,
            results_file
        );

        fclose(results_file);
    }
}

static uint64_t reserve_next_sequence(void)
{
    outgoing_sequence++;

    atomic_write_file(
        ".scadalgeria-seq",
        &outgoing_sequence,
        sizeof outgoing_sequence
    );

    return outgoing_sequence;
}

static byte_buffer_t get_cached_command_result(
    const char *command_id
)
{
    for (size_t index = 0; index < command_cache_count; index++)
    {
        command_cache_entry_t *entry = &command_cache[index];

        if (strcmp(entry->command_id, command_id) == 0)
        {
            byte_buffer_t result = {
                .data = malloc(entry->payload_length),
                .length = entry->payload_length,
            };

            if (result.data == NULL)
            {
                exit(2);
            }

            memcpy(
                result.data,
                entry->payload,
                entry->payload_length
            );

            return result;
        }
    }

    return (byte_buffer_t){0};
}

static void remember_command_result(
    const char *command_id,
    const uint8_t *payload,
    size_t payload_length
)
{
    if (payload_length > MAX_RESULT_BYTES)
    {
        fprintf(stderr, "Command result exceeds example cache size\n");
        exit(2);
    }

    if (command_cache_count == MAX_CACHED_RESULTS)
    {
        memmove(
            &command_cache[0],
            &command_cache[1],
            sizeof command_cache - sizeof command_cache[0]
        );

        command_cache_count--;
    }

    command_cache_entry_t *entry =
        &command_cache[command_cache_count++];

    memset(entry, 0, sizeof *entry);

    strncpy(
        entry->command_id,
        command_id,
        MAX_COMMAND_ID
    );

    entry->payload_length = (uint16_t)payload_length;

    memcpy(
        entry->payload,
        payload,
        payload_length
    );

    atomic_write_file(
        ".scadalgeria-results",
        command_cache,
        command_cache_count * sizeof command_cache[0]
    );
}


/* ========================================================================== */
/* STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE */
/* ========================================================================== */

static uint8_t session_key[32];
static bool session_key_available = false;
static bool authenticated = false;

static uint64_t current_unix_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    {
        perror("clock_gettime");
        exit(2);
    }

    return ((uint64_t)now.tv_sec * 1000ULL)
        + ((uint64_t)now.tv_nsec / 1000000ULL);
}

static void write_uint64_big_endian(
    uint8_t output[8],
    uint64_t value
)
{
    for (int index = 7; index >= 0; index--)
    {
        output[index] = (uint8_t)(value & 0xffu);
        value >>= 8;
    }
}

static void build_envelope_aad(
    uint64_t sequence,
    uint64_t timestamp_ms,
    uint8_t aad[16]
)
{
    write_uint64_big_endian(
        &aad[0],
        sequence
    );

    write_uint64_big_endian(
        &aad[8],
        timestamp_ms
    );
}

static byte_buffer_t copy_msgpack_buffer(msgpack_sbuffer *buffer)
{
    byte_buffer_t result = {
        .data = malloc(buffer->size),
        .length = buffer->size,
    };

    if (result.data == NULL)
    {
        exit(2);
    }

    memcpy(
        result.data,
        buffer->data,
        buffer->size
    );

    return result;
}

static void pack_string(
    msgpack_packer *packer,
    const char *value
)
{
    size_t length = strlen(value);

    msgpack_pack_str(
        packer,
        length
    );

    msgpack_pack_str_body(
        packer,
        value,
        length
    );
}

static void pack_binary(
    msgpack_packer *packer,
    const uint8_t *value,
    size_t length
)
{
    msgpack_pack_bin(
        packer,
        length
    );

    msgpack_pack_bin_body(
        packer,
        value,
        length
    );
}

static bool read_object_string(
    msgpack_object object,
    char *destination,
    size_t capacity
)
{
    if (
        object.type != MSGPACK_OBJECT_STR
        || object.via.str.size + 1 > capacity
    )
    {
        return false;
    }

    memcpy(
        destination,
        object.via.str.ptr,
        object.via.str.size
    );

    destination[object.via.str.size] = '\0';

    return true;
}

static bool read_object_binary(
    msgpack_object object,
    const uint8_t **data,
    size_t *length
)
{
    if (object.type != MSGPACK_OBJECT_BIN)
    {
        return false;
    }

    *data = (const uint8_t *)object.via.bin.ptr;
    *length = object.via.bin.size;

    return true;
}

static bool read_object_uint64(
    msgpack_object object,
    uint64_t *value
)
{
    if (object.type == MSGPACK_OBJECT_POSITIVE_INTEGER)
    {
        *value = object.via.u64;
        return true;
    }

    return false;
}

static bool read_object_boolean(
    msgpack_object object,
    bool *value
)
{
    if (object.type != MSGPACK_OBJECT_BOOLEAN)
    {
        return false;
    }

    *value = object.via.boolean;
    return true;
}

static bool read_output_bit(
    msgpack_object object,
    int *value
)
{
    if (object.type == MSGPACK_OBJECT_BOOLEAN)
    {
        *value = object.via.boolean ? 1 : 0;
        return true;
    }

    if (
        object.type == MSGPACK_OBJECT_POSITIVE_INTEGER
        && object.via.u64 <= 1
    )
    {
        *value = (int)object.via.u64;
        return true;
    }

    if (
        object.type == MSGPACK_OBJECT_FLOAT32
        || object.type == MSGPACK_OBJECT_FLOAT64
    )
    {
        double number = object.via.f64;

        if (number == 0.0 || number == 1.0)
        {
            *value = (int)number;
            return true;
        }
    }

    return false;
}

static bool hmac_sha256(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *message,
    size_t message_length,
    uint8_t output[32]
)
{
    EVP_MAC *mac = EVP_MAC_fetch(
        NULL,
        "HMAC",
        NULL
    );

    EVP_MAC_CTX *context = mac != NULL
        ? EVP_MAC_CTX_new(mac)
        : NULL;

    char digest_name[] = "SHA256";

    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST,
            digest_name,
            0
        ),
        OSSL_PARAM_construct_end(),
    };

    size_t output_length = 0;

    bool success =
        context != NULL
        && EVP_MAC_init(
            context,
            key,
            key_length,
            parameters
        ) == 1
        && EVP_MAC_update(
            context,
            message,
            message_length
        ) == 1
        && EVP_MAC_final(
            context,
            output,
            &output_length,
            32
        ) == 1
        && output_length == 32;

    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);

    return success;
}

static bool derive_session_key(
    const uint8_t *server_nonce,
    const uint8_t *client_nonce
)
{
    uint8_t salt[32];

    memcpy(&salt[0], server_nonce, 16);
    memcpy(&salt[16], client_nonce, 16);

    EVP_KDF *kdf = EVP_KDF_fetch(
        NULL,
        "HKDF",
        NULL
    );

    EVP_KDF_CTX *context = kdf != NULL
        ? EVP_KDF_CTX_new(kdf)
        : NULL;

    char digest_name[] = "SHA256";
    char info[] = "SCADA-ENC-v1";

    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            digest_name,
            0
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            (void *)configuration.api_key_token,
            strlen(configuration.api_key_token)
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt,
            sizeof salt
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            info,
            strlen(info)
        ),
        OSSL_PARAM_construct_end(),
    };

    bool success =
        context != NULL
        && EVP_KDF_derive(
            context,
            session_key,
            sizeof session_key,
            parameters
        ) == 1;

    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);

    session_key_available = success;

    return success;
}

static bool aes_gcm_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_length,
    const uint8_t nonce[12],
    const uint8_t aad[16],
    uint8_t **ciphertext,
    uint8_t gcm_tag[16]
)
{
    if (!session_key_available)
    {
        return false;
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();

    *ciphertext = malloc(plaintext_length);

    if (context == NULL || *ciphertext == NULL)
    {
        EVP_CIPHER_CTX_free(context);
        free(*ciphertext);
        *ciphertext = NULL;
        return false;
    }

    int output_length = 0;
    int total_length = 0;

    bool success =
        EVP_EncryptInit_ex2(
            context,
            EVP_aes_256_gcm(),
            session_key,
            nonce,
            NULL
        ) == 1
        && EVP_EncryptUpdate(
            context,
            NULL,
            &output_length,
            aad,
            16
        ) == 1
        && EVP_EncryptUpdate(
            context,
            *ciphertext,
            &output_length,
            plaintext,
            (int)plaintext_length
        ) == 1;

    total_length = output_length;

    success = success
        && EVP_EncryptFinal_ex(
            context,
            *ciphertext + total_length,
            &output_length
        ) == 1;

    total_length += output_length;

    success = success
        && EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_GET_TAG,
            16,
            gcm_tag
        ) == 1
        && (size_t)total_length == plaintext_length;

    EVP_CIPHER_CTX_free(context);

    if (!success)
    {
        free(*ciphertext);
        *ciphertext = NULL;
    }

    return success;
}

static bool aes_gcm_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t nonce[12],
    const uint8_t gcm_tag[16],
    const uint8_t aad[16],
    uint8_t **plaintext
)
{
    if (!session_key_available)
    {
        return false;
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();

    *plaintext = malloc(ciphertext_length);

    if (context == NULL || *plaintext == NULL)
    {
        EVP_CIPHER_CTX_free(context);
        free(*plaintext);
        *plaintext = NULL;
        return false;
    }

    int output_length = 0;
    int total_length = 0;

    bool success =
        EVP_DecryptInit_ex2(
            context,
            EVP_aes_256_gcm(),
            session_key,
            nonce,
            NULL
        ) == 1
        && EVP_DecryptUpdate(
            context,
            NULL,
            &output_length,
            aad,
            16
        ) == 1
        && EVP_DecryptUpdate(
            context,
            *plaintext,
            &output_length,
            ciphertext,
            (int)ciphertext_length
        ) == 1;

    total_length = output_length;

    success = success
        && EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_TAG,
            16,
            (void *)gcm_tag
        ) == 1
        && EVP_DecryptFinal_ex(
            context,
            *plaintext + total_length,
            &output_length
        ) == 1;

    EVP_CIPHER_CTX_free(context);

    if (!success)
    {
        free(*plaintext);
        *plaintext = NULL;
    }

    return success;
}


/* ========================================================================== */
/* STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE */
/* ========================================================================== */

static byte_buffer_t build_auth_response(
    const uint8_t client_nonce[16],
    const uint8_t proof[32]
)
{
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(
        &packer,
        &buffer,
        msgpack_sbuffer_write
    );

    msgpack_pack_array(&packer, 2);
    pack_binary(&packer, client_nonce, 16);
    pack_binary(&packer, proof, 32);

    byte_buffer_t result = copy_msgpack_buffer(&buffer);

    msgpack_sbuffer_destroy(&buffer);

    return result;
}

static byte_buffer_t build_digital_input_telemetry(int input_value)
{
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(
        &packer,
        &buffer,
        msgpack_sbuffer_write
    );

    /* TagFrameBatchDto = [ Frames, TraceId, SchemaVersion ] */
    msgpack_pack_array(&packer, 3);

    msgpack_pack_array(&packer, 1);

    /* TagFrameDto = [ Address, ValNum, ValStr, TsUnixMs, Quality ] */
    msgpack_pack_array(&packer, 5);
    pack_string(&packer, INPUT_TAG_ADDRESS);
    msgpack_pack_double(&packer, (double)input_value);
    msgpack_pack_nil(&packer);
    msgpack_pack_int64(&packer, 0);
    msgpack_pack_int(&packer, 192);

    msgpack_pack_nil(&packer);
    msgpack_pack_int(&packer, 1);

    byte_buffer_t result = copy_msgpack_buffer(&buffer);
    msgpack_sbuffer_destroy(&buffer);

    return result;
}

static byte_buffer_t build_command_result(
    const char *command_id,
    bool success,
    const char *error_message,
    int applied_value
)
{
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(
        &packer,
        &buffer,
        msgpack_sbuffer_write
    );

    msgpack_pack_array(&packer, 5);
    pack_string(&packer, command_id);

    if (success)
    {
        msgpack_pack_true(&packer);
    }
    else
    {
        msgpack_pack_false(&packer);
    }

    if (error_message == NULL)
    {
        msgpack_pack_nil(&packer);
    }
    else
    {
        pack_string(&packer, error_message);
    }

    if (success)
    {
        char data[64];

        snprintf(
            data,
            sizeof data,
            "{\"appliedValue\":%d}",
            applied_value
        );

        pack_string(&packer, data);
    }
    else
    {
        msgpack_pack_nil(&packer);
    }

    msgpack_pack_int(&packer, 1);

    byte_buffer_t result = copy_msgpack_buffer(&buffer);
    msgpack_sbuffer_destroy(&buffer);

    return result;
}

static byte_buffer_t encrypt_scadalgeria_payload(
    byte_buffer_t inner_message
)
{
    uint64_t sequence = reserve_next_sequence();
    uint64_t timestamp_ms = current_unix_milliseconds();

    uint8_t nonce[12];
    uint8_t aad[16];
    uint8_t gcm_tag[16];
    uint8_t *ciphertext = NULL;

    if (RAND_bytes(nonce, sizeof nonce) != 1)
    {
        fprintf(stderr, "Secure random generation failed\n");
        exit(2);
    }

    build_envelope_aad(
        sequence,
        timestamp_ms,
        aad
    );

    if (!aes_gcm_encrypt(
        inner_message.data,
        inner_message.length,
        nonce,
        aad,
        &ciphertext,
        gcm_tag
    ))
    {
        fprintf(stderr, "AES-GCM encryption failed\n");
        exit(2);
    }

    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(
        &packer,
        &buffer,
        msgpack_sbuffer_write
    );

    msgpack_pack_array(&packer, 6);
    pack_string(&packer, configuration.api_key_id);
    pack_binary(&packer, nonce, sizeof nonce);
    pack_binary(&packer, ciphertext, inner_message.length);
    pack_binary(&packer, gcm_tag, sizeof gcm_tag);
    msgpack_pack_uint64(&packer, sequence);
    msgpack_pack_uint64(&packer, timestamp_ms);

    free(ciphertext);

    byte_buffer_t result = copy_msgpack_buffer(&buffer);
    msgpack_sbuffer_destroy(&buffer);

    return result;
}

static byte_buffer_t decrypt_scadalgeria_payload(
    const uint8_t *payload,
    size_t payload_length
)
{
    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    size_t offset = 0;

    if (
        !msgpack_unpack_next(
            &unpacked,
            (const char *)payload,
            payload_length,
            &offset
        )
        || unpacked.data.type != MSGPACK_OBJECT_ARRAY
        || unpacked.data.via.array.size != 6
    )
    {
        msgpack_unpacked_destroy(&unpacked);
        fprintf(stderr, "Malformed encrypted envelope\n");
        exit(2);
    }

    msgpack_object *fields = unpacked.data.via.array.ptr;

    char key_id[128];
    const uint8_t *nonce;
    const uint8_t *ciphertext;
    const uint8_t *gcm_tag;
    size_t nonce_length;
    size_t ciphertext_length;
    size_t tag_length;
    uint64_t sequence;
    uint64_t timestamp_ms;

    bool valid =
        read_object_string(fields[0], key_id, sizeof key_id)
        && read_object_binary(fields[1], &nonce, &nonce_length)
        && read_object_binary(fields[2], &ciphertext, &ciphertext_length)
        && read_object_binary(fields[3], &gcm_tag, &tag_length)
        && read_object_uint64(fields[4], &sequence)
        && read_object_uint64(fields[5], &timestamp_ms)
        && strcmp(key_id, configuration.api_key_id) == 0
        && nonce_length == 12
        && tag_length == 16;

    if (!valid)
    {
        msgpack_unpacked_destroy(&unpacked);
        fprintf(stderr, "Encrypted envelope validation failed\n");
        exit(2);
    }

    uint8_t aad[16];
    uint8_t *plaintext = NULL;

    build_envelope_aad(
        sequence,
        timestamp_ms,
        aad
    );

    if (!aes_gcm_decrypt(
        ciphertext,
        ciphertext_length,
        nonce,
        gcm_tag,
        aad,
        &plaintext
    ))
    {
        msgpack_unpacked_destroy(&unpacked);
        fprintf(stderr, "AES-GCM authentication failed\n");
        exit(2);
    }

    msgpack_unpacked_destroy(&unpacked);

    return (byte_buffer_t){
        .data = plaintext,
        .length = ciphertext_length,
    };
}


/* ========================================================================== */
/* STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY */
/* ========================================================================== */

static MQTTClient mqtt_client;

static void publish_raw_qos1(
    const char *topic,
    byte_buffer_t payload
)
{
    MQTTClient_message message = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;

    message.payload = payload.data;
    message.payloadlen = (int)payload.length;
    message.qos = MQTT_QOS;
    message.retained = 0;

    int rc = MQTTClient_publishMessage(
        mqtt_client,
        topic,
        &message,
        &token
    );

    if (rc != MQTTCLIENT_SUCCESS)
    {
        fprintf(stderr, "MQTT publish failed locally: %d\n", rc);
        exit(2);
    }

    rc = MQTTClient_waitForCompletion(
        mqtt_client,
        token,
        10000L
    );

    if (rc != MQTTCLIENT_SUCCESS)
    {
        fprintf(stderr, "MQTT PUBACK wait failed: %d\n", rc);
        exit(2);
    }
}

static void publish_encrypted_message(
    const char *topic,
    byte_buffer_t inner_message
)
{
    byte_buffer_t encrypted = encrypt_scadalgeria_payload(
        inner_message
    );

    publish_raw_qos1(
        topic,
        encrypted
    );

    free_byte_buffer(encrypted);
}

static int subscribe_exact_qos1(
    MQTTClient client,
    const char *topic
)
{
    /*
     * MQTTClient_subscribe() only reports success/failure. The one-topic
     * subscribeMany() variant also writes the broker's granted QoS back into
     * the qos array, which lets this example reject a downgraded grant.
     */
    char *topics[1] = {
        (char *)topic,
    };

    int granted_qos[1] = {
        1,
    };

    int result = MQTTClient_subscribeMany(
        client,
        1,
        topics,
        granted_qos
    );

    if (result != MQTTCLIENT_SUCCESS)
    {
        return result;
    }

    if (granted_qos[0] != 1)
    {
        return MQTT_BAD_SUBSCRIBE;
    }

    return MQTTCLIENT_SUCCESS;
}

static void authenticate_with_scadalgeria(
    const uint8_t *challenge_payload,
    size_t challenge_length
)
{
    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    size_t offset = 0;

    if (
        !msgpack_unpack_next(
            &unpacked,
            (const char *)challenge_payload,
            challenge_length,
            &offset
        )
        || unpacked.data.type != MSGPACK_OBJECT_ARRAY
        || unpacked.data.via.array.size != 2
    )
    {
        msgpack_unpacked_destroy(&unpacked);
        fprintf(stderr, "Malformed authentication challenge\n");
        return;
    }

    msgpack_object *fields = unpacked.data.via.array.ptr;

    const uint8_t *server_nonce;
    size_t server_nonce_length;
    uint64_t expires_at_ms;

    bool valid =
        read_object_binary(
            fields[0],
            &server_nonce,
            &server_nonce_length
        )
        && read_object_uint64(
            fields[1],
            &expires_at_ms
        )
        && server_nonce_length == 16
        && current_unix_milliseconds() < expires_at_ms;

    if (!valid)
    {
        msgpack_unpacked_destroy(&unpacked);
        fprintf(stderr, "Expired or invalid authentication challenge\n");
        return;
    }

    uint8_t client_nonce[16];

    if (RAND_bytes(client_nonce, sizeof client_nonce) != 1)
    {
        msgpack_unpacked_destroy(&unpacked);
        fprintf(stderr, "Secure random generation failed\n");
        return;
    }

    size_t client_id_length = strlen(configuration.client_id);
    size_t proof_message_length = 32 + client_id_length;

    uint8_t *proof_message = malloc(proof_message_length);

    if (proof_message == NULL)
    {
        msgpack_unpacked_destroy(&unpacked);
        return;
    }

    memcpy(&proof_message[0], server_nonce, 16);
    memcpy(&proof_message[16], client_nonce, 16);
    memcpy(&proof_message[32], configuration.client_id, client_id_length);

    uint8_t proof[32];

    bool proof_ok = hmac_sha256(
        (const uint8_t *)configuration.api_key_token,
        strlen(configuration.api_key_token),
        proof_message,
        proof_message_length,
        proof
    );

    free(proof_message);

    if (
        !proof_ok
        || !derive_session_key(
            server_nonce,
            client_nonce
        )
    )
    {
        msgpack_unpacked_destroy(&unpacked);
        fprintf(stderr, "Authentication cryptography failed\n");
        return;
    }

    byte_buffer_t auth_response = build_auth_response(
        client_nonce,
        proof
    );

    publish_raw_qos1(
        configuration.auth_response_topic,
        auth_response
    );

    free_byte_buffer(auth_response);

    /* Paho waits for SUBACK. MQTT_BAD_SUBSCRIBE means broker returned 0x80. */
    int subscribe_result = MQTTClient_subscribe(
        mqtt_client,
        configuration.commands_topic,
        MQTT_QOS
    );

    if (subscribe_result != MQTTCLIENT_SUCCESS)
    {
        session_key_available = false;
        authenticated = false;

        fprintf(
            stderr,
            "Post-auth command subscription rejected: %d\n",
            subscribe_result
        );

        msgpack_unpacked_destroy(&unpacked);
        return;
    }

    authenticated = true;

    printf(
        "SCADALGERIA session authenticated; telemetry and commands are enabled\n"
    );

    msgpack_unpacked_destroy(&unpacked);
}

static void publish_digital_input_telemetry(void)
{
    int input_value = read_digital_input();

    byte_buffer_t telemetry = build_digital_input_telemetry(
        input_value
    );

    publish_encrypted_message(
        configuration.telemetry_topic,
        telemetry
    );

    free_byte_buffer(telemetry);

    printf(
        "Telemetry sent: %s=%d\n",
        INPUT_TAG_ADDRESS,
        input_value
    );
}


/* ========================================================================== */
/* STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT */
/* ========================================================================== */

static void handle_scadalgeria_command(
    const uint8_t *encrypted_payload,
    size_t encrypted_length
)
{
    byte_buffer_t plaintext = decrypt_scadalgeria_payload(
        encrypted_payload,
        encrypted_length
    );

    msgpack_unpacked unpacked;
    msgpack_unpacked_init(&unpacked);

    size_t offset = 0;

    if (
        !msgpack_unpack_next(
            &unpacked,
            (const char *)plaintext.data,
            plaintext.length,
            &offset
        )
        || unpacked.data.type != MSGPACK_OBJECT_ARRAY
        || unpacked.data.via.array.size != 10
    )
    {
        fprintf(stderr, "Malformed CommandDto\n");
        msgpack_unpacked_destroy(&unpacked);
        free_byte_buffer(plaintext);
        return;
    }

    msgpack_object *fields = unpacked.data.via.array.ptr;

    char command_id[MAX_COMMAND_ID + 1];
    char tag_address[256];

    if (
        !read_object_string(
            fields[0],
            command_id,
            sizeof command_id
        )
        || command_id[0] == '\0'
        || !read_object_string(
            fields[1],
            tag_address,
            sizeof tag_address
        )
    )
    {
        fprintf(stderr, "Command identity is malformed\n");
        msgpack_unpacked_destroy(&unpacked);
        free_byte_buffer(plaintext);
        return;
    }

    byte_buffer_t cached_result = get_cached_command_result(
        command_id
    );

    if (cached_result.data != NULL)
    {
        printf(
            "Command redelivery detected: %s; returning cached result\n",
            command_id
        );

        publish_encrypted_message(
            configuration.command_result_topic,
            cached_result
        );

        free_byte_buffer(cached_result);
        msgpack_unpacked_destroy(&unpacked);
        free_byte_buffer(plaintext);
        return;
    }

    bool command_success = false;
    int applied_value = 0;
    char error_message[257] = {0};

    uint64_t expiry_epoch_seconds;
    uint64_t schema_version;
    bool requires_confirmation;
    bool confirmed;

    if (
        !read_object_uint64(
            fields[9],
            &schema_version
        )
        || schema_version != 2
    )
    {
        snprintf(
            error_message,
            sizeof error_message,
            "Unsupported CommandDto schema version"
        );
    }
    else if (strcmp(tag_address, OUTPUT_TAG_ADDRESS) != 0)
    {
        snprintf(
            error_message,
            sizeof error_message,
            "Unsupported command address: %s",
            tag_address
        );
    }
    else if (
        !read_object_uint64(
            fields[4],
            &expiry_epoch_seconds
        )
        || expiry_epoch_seconds <= current_unix_milliseconds() / 1000ULL
    )
    {
        snprintf(
            error_message,
            sizeof error_message,
            "Command expired or has invalid Expiry"
        );
    }
    else if (
        !read_object_boolean(
            fields[7],
            &requires_confirmation
        )
        || !read_object_boolean(
            fields[8],
            &confirmed
        )
    )
    {
        snprintf(
            error_message,
            sizeof error_message,
            "Command confirmation fields must be booleans"
        );
    }
    else if (requires_confirmation && !confirmed)
    {
        snprintf(
            error_message,
            sizeof error_message,
            "Command requires operator confirmation"
        );
    }
    else if (!read_output_bit(fields[2], &applied_value))
    {
        snprintf(
            error_message,
            sizeof error_message,
            "do.output1 accepts only 0 or 1"
        );
    }
    else
    {
        write_digital_output(applied_value);
        command_success = true;

        printf(
            "Command applied: %s=%d\n",
            OUTPUT_TAG_ADDRESS,
            applied_value
        );
    }

    byte_buffer_t result = build_command_result(
        command_id,
        command_success,
        command_success ? NULL : error_message,
        applied_value
    );

    remember_command_result(
        command_id,
        result.data,
        result.length
    );

    publish_encrypted_message(
        configuration.command_result_topic,
        result
    );

    free_byte_buffer(result);
    msgpack_unpacked_destroy(&unpacked);
    free_byte_buffer(plaintext);
}


/* ========================================================================== */
/* STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP */
/*                                                                            */
/* MQTTClient_receive() uses a short timeout so the same thread can service   */
/* incoming broker traffic and the one-second telemetry timer.                */
/* ========================================================================== */

static void clear_authenticated_session(void)
{
    OPENSSL_cleanse(
        session_key,
        sizeof session_key
    );

    session_key_available = false;
    authenticated = false;
}

static bool connect_and_start_authentication(void)
{
    clear_authenticated_session();

    MQTTClient_connectOptions options =
        MQTTClient_connectOptions_initializer;

    options.MQTTVersion = MQTTVERSION_3_1_1;
    options.cleansession = 1;
    options.username = configuration.mqtt_username;

    /* The Direct Firmware API token is not an MQTT password. */
    options.password = "";

    int connect_result = MQTTClient_connect(
        mqtt_client,
        &options
    );

    if (connect_result != MQTTCLIENT_SUCCESS)
    {
        fprintf(
            stderr,
            "MQTT CONNECT failed: %d\n",
            connect_result
        );

        return false;
    }

    int subscribe_result = MQTTClient_subscribe(
        mqtt_client,
        configuration.auth_challenge_topic,
        MQTT_QOS
    );

    if (subscribe_result != MQTTCLIENT_SUCCESS)
    {
        fprintf(
            stderr,
            "Pre-auth challenge subscription failed: %d\n",
            subscribe_result
        );

        MQTTClient_disconnect(
            mqtt_client,
            1000
        );

        return false;
    }

    printf(
        "MQTT connected; waiting for a fresh SCADALGERIA challenge\n"
    );

    return true;
}

int main(void)
{
    load_configuration();
    load_device_state();
    initialize_digital_io();

    char broker_uri[512];

    snprintf(
        broker_uri,
        sizeof broker_uri,
        "tcp://%s:%d",
        configuration.host,
        configuration.port
    );

    int create_result = MQTTClient_create(
        &mqtt_client,
        broker_uri,
        configuration.client_id,
        MQTTCLIENT_PERSISTENCE_NONE,
        NULL
    );

    if (create_result != MQTTCLIENT_SUCCESS)
    {
        fprintf(stderr, "MQTTClient_create failed: %d\n", create_result);
        return 2;
    }

    unsigned int reconnect_delay_seconds = 1;
    uint64_t last_telemetry_ms = 0;

    for (;;)
    {
        if (!MQTTClient_isConnected(mqtt_client))
        {
            if (!connect_and_start_authentication())
            {
                sleep(reconnect_delay_seconds);

                reconnect_delay_seconds *= 2;
                if (reconnect_delay_seconds > 30)
                {
                    reconnect_delay_seconds = 30;
                }

                continue;
            }

            reconnect_delay_seconds = 1;
        }

        char *topic_name = NULL;
        int topic_length = 0;
        MQTTClient_message *message = NULL;

        int receive_result = MQTTClient_receive(
            mqtt_client,
            &topic_name,
            &topic_length,
            &message,
            100
        );

        if (receive_result != MQTTCLIENT_SUCCESS)
        {
            clear_authenticated_session();
            MQTTClient_disconnect(mqtt_client, 0);
            continue;
        }

        if (message != NULL && topic_name != NULL)
        {
            if (
                strcmp(
                    topic_name,
                    configuration.auth_challenge_topic
                ) == 0
            )
            {
                authenticate_with_scadalgeria(
                    message->payload,
                    (size_t)message->payloadlen
                );
            }
            else if (
                authenticated
                && strcmp(
                    topic_name,
                    configuration.commands_topic
                ) == 0
            )
            {
                handle_scadalgeria_command(
                    message->payload,
                    (size_t)message->payloadlen
                );
            }

            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic_name);
        }

        uint64_t now_ms = current_unix_milliseconds();

        if (
            authenticated
            && now_ms - last_telemetry_ms >= 1000ULL
        )
        {
            publish_digital_input_telemetry();
            last_telemetry_ms = now_ms;

            /* Also obey the copied configuration telemetryPolicy in production. */
        }
    }
}
