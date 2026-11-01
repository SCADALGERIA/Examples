/*
 * SCADALGERIA Direct Firmware example — Raspberry Pi 5 / C++
 *
 * Complete Direct Firmware flow:
 *
 *     BCM17 -> "di.input1" telemetry -> SCADALGERIA
 *     BCM27 <- "do.output1" command  <- SCADALGERIA
 *
 * The example intentionally keeps the SCADALGERIA-specific protocol visible.
 * Paho MQTT C++, msgpack-c, OpenSSL and libgpiod provide the generic pieces.
 */


// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

#include <mqtt/client.h>
#include <mqtt/reason_code.h>

#include <gpiod.h>
#include <msgpack.hpp>
#include <nlohmann/json.hpp>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

using Bytes = std::vector<std::uint8_t>;


// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
//
// Save Connection → Copy firmware configuration → Copy JSON as
// `scadalgeria-connection.json`. The document contains no API-key secret.
// Supply that secret separately through SCADALGERIA_API_KEY.
// ============================================================================

struct Configuration
{
    std::string host;
    int port;
    std::string clientId;
    std::string mqttUsername;
    std::string apiKeyId;
    std::string apiKeyToken;
    std::string authChallengeTopic;
    std::string authResponseTopic;
    std::string telemetryTopic;
    std::string commandsTopic;
    std::string commandResultTopic;
    std::string gpioChip;
};

static std::string requiredSecret(const char *name)
{
    const char *value = std::getenv(name);
    if (value == nullptr || *value == '\0')
        throw std::runtime_error(std::string("Missing required secret: ") + name);
    return value;
}

static std::string environmentValueOr(const char *name, const char *fallback)
{
    const char *value = std::getenv(name);
    return value != nullptr && *value != '\0' ? value : fallback;
}

static std::string createUniqueClientId()
{
    std::array<unsigned char, 8> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
        throw std::runtime_error("RAND_bytes failed while creating MQTT ClientId");
    static constexpr char Hex[] = "0123456789abcdef";
    std::string value = "scada-";
    for (auto byte : random) {
        value.push_back(Hex[(byte >> 4) & 0x0F]);
        value.push_back(Hex[byte & 0x0F]);
    }
    return value;
}

static std::string resolveClientTopic(std::string topicTemplate, const std::string &clientId)
{
    constexpr std::string_view Marker = "{clientId}";
    const auto first = topicTemplate.find(Marker);
    if (first == std::string::npos || topicTemplate.find(Marker, first + Marker.size()) != std::string::npos)
        throw std::runtime_error("Authentication topic template must contain exactly one {clientId}");
    topicTemplate.replace(first, Marker.size(), clientId);
    return topicTemplate;
}

static void requireBooleanTag(const nlohmann::json &manifest, const char *address, const char *direction)
{
    std::size_t count = 0;
    for (const auto &tag : manifest.at("tags")) {
        if (tag.at("address").get<std::string>() == address) {
            ++count;
            if (tag.at("dataType").get<std::string>() != "Boolean" || tag.at("direction").get<std::string>() != direction)
                throw std::runtime_error(std::string("Tag '") + address + "' must be Boolean/" + direction);
        }
    }
    if (count != 1)
        throw std::runtime_error(std::string("Copied configuration must contain exactly one tag '") + address + "'");
}

static Configuration loadConfiguration()
{
    const auto path = environmentValueOr("SCADALGERIA_CONFIG_FILE", "scadalgeria-connection.json");
    std::ifstream input(path);
    if (!input) throw std::runtime_error("Unable to open copied SCADALGERIA connection configuration");

    nlohmann::json manifest;
    input >> manifest;

    if (manifest.at("schema") != "scadalgeria.direct-firmware.connection" || manifest.at("schemaVersion") != 1)
        throw std::runtime_error("Unsupported SCADALGERIA connection configuration schema");

    const auto &connection = manifest.at("connection");
    const auto &identity = manifest.at("identity");
    const auto &mqtt = manifest.at("mqtt");
    const auto &broker = mqtt.at("broker");
    const auto &topics = mqtt.at("topics");
    const auto &qos = mqtt.at("qos");
    const auto &authentication = manifest.at("authentication");
    const auto &encryption = manifest.at("encryption");
    const auto &kdf = encryption.at("sessionKeyDerivation");
    const auto &secrets = manifest.at("secrets");

    if (!connection.at("enabled").get<bool>()) throw std::runtime_error("The copied Connection is disabled");
    if (mqtt.at("protocol") != "3.1.1" || !mqtt.at("cleanSession").get<bool>()) throw std::runtime_error("MQTT 3.1.1 with cleanSession=true is required");
    if (broker.at("transport") != "tcp") throw std::runtime_error("Unsupported copied MQTT transport");
    if (mqtt.at("clientIdRequirement") != "unique-per-active-session") throw std::runtime_error("Unsupported clientIdRequirement");
    if (qos.at("telemetry") != 1 || qos.at("commands") != 1 || qos.at("commandResults") != 1) throw std::runtime_error("Copied telemetry/command/result QoS must be 1");
    if (authentication.at("scheme") != "HMAC-SHA256" || encryption.at("scheme") != "AES-256-GCM") throw std::runtime_error("Unsupported authentication/encryption contract");
    if (kdf.at("algorithm") != "HKDF-SHA256" || kdf.at("info") != "SCADA-ENC-v1") throw std::runtime_error("Unsupported session-key derivation contract");
    if (secrets.at("apiKeySecretIncluded").get<bool>()) throw std::runtime_error("Connection Copy JSON must never contain the API-key secret");

    requireBooleanTag(manifest, "di.input1", "Input");
    requireBooleanTag(manifest, "do.output1", "Output");

    const auto clientId = createUniqueClientId();
    return Configuration{
        .host = broker.at("host").get<std::string>(),
        .port = broker.at("port").get<int>(),
        .clientId = clientId,
        .mqttUsername = mqtt.at("username").get<std::string>(),
        .apiKeyId = identity.at("keyId").get<std::string>(),
        .apiKeyToken = requiredSecret("SCADALGERIA_API_KEY"),
        .authChallengeTopic = resolveClientTopic(topics.at("authenticationChallenge").get<std::string>(), clientId),
        .authResponseTopic = resolveClientTopic(topics.at("authenticationResponse").get<std::string>(), clientId),
        .telemetryTopic = topics.at("telemetry").get<std::string>(),
        .commandsTopic = topics.at("commands").get<std::string>(),
        .commandResultTopic = topics.at("commandResults").get<std::string>(),
        .gpioChip = environmentValueOr("SCADALGERIA_GPIO_CHIP", "/dev/gpiochip0"),
    };
}

static const Configuration configuration = loadConfiguration();

#define INPUT_TAG_ADDRESS  "di.input1"
#define OUTPUT_TAG_ADDRESS "do.output1"
#define MQTT_QOS 1

// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
//
// BCM17 is an active-low input with pull-up.
// BCM27 is the set-state output controlled by "do.output1".
//
// Use correct isolation/driver hardware for field equipment.
// ============================================================================

class DigitalIo
{
public:
    DigitalIo()
    {
        const unsigned inputOffset = 17;
        const unsigned outputOffset = 27;

        auto *inputSettings = gpiod_line_settings_new();
        auto *outputSettings = gpiod_line_settings_new();
        auto *lineConfig = gpiod_line_config_new();
        auto *requestConfig = gpiod_request_config_new();

        if (
            inputSettings == nullptr
            || outputSettings == nullptr
            || lineConfig == nullptr
            || requestConfig == nullptr
        )
        {
            throw std::runtime_error(
                "Unable to allocate libgpiod configuration"
            );
        }

        gpiod_line_settings_set_direction(
            inputSettings,
            GPIOD_LINE_DIRECTION_INPUT
        );

        gpiod_line_settings_set_bias(
            inputSettings,
            GPIOD_LINE_BIAS_PULL_UP
        );

        gpiod_line_settings_set_direction(
            outputSettings,
            GPIOD_LINE_DIRECTION_OUTPUT
        );

        gpiod_line_settings_set_output_value(
            outputSettings,
            GPIOD_LINE_VALUE_INACTIVE
        );

        if (
            gpiod_line_config_add_line_settings(
                lineConfig,
                &inputOffset,
                1,
                inputSettings
            ) < 0
            || gpiod_line_config_add_line_settings(
                lineConfig,
                &outputOffset,
                1,
                outputSettings
            ) < 0
        )
        {
            throw std::runtime_error(
                "Unable to configure GPIO lines"
            );
        }

        gpiod_request_config_set_consumer(
            requestConfig,
            "scadalgeria-example"
        );

        chip_ = gpiod_chip_open(
            configuration.gpioChip.c_str()
        );

        if (chip_ == nullptr)
        {
            throw std::runtime_error(
                "Unable to open GPIO chip"
            );
        }

        request_ = gpiod_chip_request_lines(
            chip_,
            requestConfig,
            lineConfig
        );

        gpiod_request_config_free(requestConfig);
        gpiod_line_config_free(lineConfig);
        gpiod_line_settings_free(inputSettings);
        gpiod_line_settings_free(outputSettings);

        if (request_ == nullptr)
        {
            throw std::runtime_error(
                "Unable to request GPIO lines"
            );
        }
    }

    ~DigitalIo()
    {
        if (request_ != nullptr)
        {
            gpiod_line_request_release(request_);
        }

        if (chip_ != nullptr)
        {
            gpiod_chip_close(chip_);
        }
    }

    int readInput() const
    {
        auto value = gpiod_line_request_get_value(
            request_,
            17
        );

        if (value < 0)
        {
            throw std::runtime_error(
                "GPIO input read failed"
            );
        }

        return value == GPIOD_LINE_VALUE_INACTIVE
            ? 1
            : 0;
    }

    void writeOutput(int value)
    {
        auto lineValue = value == 1
            ? GPIOD_LINE_VALUE_ACTIVE
            : GPIOD_LINE_VALUE_INACTIVE;

        if (
            gpiod_line_request_set_value(
                request_,
                27,
                lineValue
            ) < 0
        )
        {
            throw std::runtime_error(
                "GPIO output write failed"
            );
        }
    }

private:
    gpiod_chip *chip_ = nullptr;
    gpiod_line_request *request_ = nullptr;
};


// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
// ============================================================================

struct CachedCommandResult
{
    char commandId[129]{};
    std::uint16_t payloadLength{};
    std::uint8_t payload[512]{};
};

class DeviceState
{
public:
    DeviceState()
    {
        std::ifstream sequenceFile(
            ".scadalgeria-seq",
            std::ios::binary
        );

        if (sequenceFile)
        {
            sequenceFile.read(
                reinterpret_cast<char *>(&sequence_),
                sizeof sequence_
            );
        }

        std::ifstream resultsFile(
            ".scadalgeria-results",
            std::ios::binary
        );

        while (
            resultsCount_ < results_.size()
            && resultsFile.read(
                reinterpret_cast<char *>(&results_[resultsCount_]),
                sizeof(CachedCommandResult)
            )
        )
        {
            resultsCount_++;
        }
    }

    std::uint64_t reserveNextSequence()
    {
        sequence_++;

        std::ofstream temporary(
            ".scadalgeria-seq.tmp",
            std::ios::binary
        );

        temporary.write(
            reinterpret_cast<const char *>(&sequence_),
            sizeof sequence_
        );

        temporary.close();

        std::rename(
            ".scadalgeria-seq.tmp",
            ".scadalgeria-seq"
        );

        return sequence_;
    }

    std::optional<Bytes> getCommandResult(
        const std::string &commandId
    ) const
    {
        for (std::size_t index = 0; index < resultsCount_; index++)
        {
            const auto &entry = results_[index];

            if (commandId == entry.commandId)
            {
                return Bytes(
                    entry.payload,
                    entry.payload + entry.payloadLength
                );
            }
        }

        return std::nullopt;
    }

    void rememberCommandResult(
        const std::string &commandId,
        const Bytes &payload
    )
    {
        if (payload.size() > sizeof results_[0].payload)
        {
            throw std::runtime_error(
                "Command result exceeds example cache size"
            );
        }

        if (resultsCount_ == results_.size())
        {
            std::move(
                results_.begin() + 1,
                results_.end(),
                results_.begin()
            );

            resultsCount_--;
        }

        auto &entry = results_[resultsCount_++];
        entry = {};

        std::strncpy(
            entry.commandId,
            commandId.c_str(),
            sizeof entry.commandId - 1
        );

        entry.payloadLength = static_cast<std::uint16_t>(
            payload.size()
        );

        std::copy(
            payload.begin(),
            payload.end(),
            entry.payload
        );

        saveResults();
    }

private:
    void saveResults() const
    {
        std::ofstream temporary(
            ".scadalgeria-results.tmp",
            std::ios::binary
        );

        temporary.write(
            reinterpret_cast<const char *>(results_.data()),
            static_cast<std::streamsize>(
                resultsCount_ * sizeof(CachedCommandResult)
            )
        );

        temporary.close();

        std::rename(
            ".scadalgeria-results.tmp",
            ".scadalgeria-results"
        );
    }

    std::uint64_t sequence_ = 0;
    std::array<CachedCommandResult, 64> results_{};
    std::size_t resultsCount_ = 0;
};

static DeviceState deviceState;


// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
// ============================================================================

static std::array<std::uint8_t, 32> sessionKey{};
static bool sessionKeyAvailable = false;
static bool authenticated = false;

static std::uint64_t currentUnixMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

static std::array<std::uint8_t, 16> buildEnvelopeAad(
    std::uint64_t sequence,
    std::uint64_t timestampMs
)
{
    std::array<std::uint8_t, 16> aad{};

    for (int index = 7; index >= 0; index--)
    {
        aad[index] = static_cast<std::uint8_t>(
            sequence & 0xffu
        );

        sequence >>= 8;

        aad[8 + index] = static_cast<std::uint8_t>(
            timestampMs & 0xffu
        );

        timestampMs >>= 8;
    }

    return aad;
}

static Bytes hmacSha256(const Bytes &message)
{
    EVP_MAC *mac = EVP_MAC_fetch(
        nullptr,
        "HMAC",
        nullptr
    );

    EVP_MAC_CTX *context = mac != nullptr
        ? EVP_MAC_CTX_new(mac)
        : nullptr;

    if (context == nullptr)
    {
        EVP_MAC_free(mac);
        throw std::runtime_error("Unable to create HMAC context");
    }

    char digestName[] = "SHA256";

    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST,
            digestName,
            0
        ),
        OSSL_PARAM_construct_end(),
    };

    std::array<std::uint8_t, 32> output{};
    std::size_t outputLength = 0;

    bool success =
        EVP_MAC_init(
            context,
            reinterpret_cast<const std::uint8_t *>(
                configuration.apiKeyToken.data()
            ),
            configuration.apiKeyToken.size(),
            parameters
        ) == 1
        && EVP_MAC_update(
            context,
            message.data(),
            message.size()
        ) == 1
        && EVP_MAC_final(
            context,
            output.data(),
            &outputLength,
            output.size()
        ) == 1
        && outputLength == output.size();

    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);

    if (!success)
    {
        throw std::runtime_error("HMAC-SHA256 failed");
    }

    return Bytes(
        output.begin(),
        output.end()
    );
}

static void deriveSessionKey(
    std::span<const std::uint8_t> serverNonce,
    std::span<const std::uint8_t> clientNonce
)
{
    Bytes salt;
    salt.reserve(serverNonce.size() + clientNonce.size());

    salt.insert(
        salt.end(),
        serverNonce.begin(),
        serverNonce.end()
    );

    salt.insert(
        salt.end(),
        clientNonce.begin(),
        clientNonce.end()
    );

    EVP_KDF *kdf = EVP_KDF_fetch(
        nullptr,
        "HKDF",
        nullptr
    );

    EVP_KDF_CTX *context = kdf != nullptr
        ? EVP_KDF_CTX_new(kdf)
        : nullptr;

    if (context == nullptr)
    {
        EVP_KDF_free(kdf);
        throw std::runtime_error("Unable to create HKDF context");
    }

    char digestName[] = "SHA256";
    char info[] = "SCADA-ENC-v1";

    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            digestName,
            0
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            (void *)configuration.apiKeyToken.data(),
            configuration.apiKeyToken.size()
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt.data(),
            salt.size()
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            info,
            std::strlen(info)
        ),
        OSSL_PARAM_construct_end(),
    };

    if (
        EVP_KDF_derive(
            context,
            sessionKey.data(),
            sessionKey.size(),
            parameters
        ) != 1
    )
    {
        EVP_KDF_CTX_free(context);
        EVP_KDF_free(kdf);
        throw std::runtime_error("HKDF-SHA256 failed");
    }

    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);

    sessionKeyAvailable = true;
}

static Bytes aesGcmEncrypt(
    const Bytes &plaintext,
    const std::array<std::uint8_t, 12> &nonce,
    const std::array<std::uint8_t, 16> &aad,
    std::array<std::uint8_t, 16> &gcmTag
)
{
    if (!sessionKeyAvailable)
    {
        throw std::runtime_error(
            "SCADALGERIA session is not authenticated"
        );
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();

    if (context == nullptr)
    {
        throw std::runtime_error("Unable to create AES-GCM context");
    }

    Bytes ciphertext(plaintext.size());

    int outputLength = 0;
    int totalLength = 0;

    bool success =
        EVP_EncryptInit_ex2(
            context,
            EVP_aes_256_gcm(),
            sessionKey.data(),
            nonce.data(),
            nullptr
        ) == 1
        && EVP_EncryptUpdate(
            context,
            nullptr,
            &outputLength,
            aad.data(),
            aad.size()
        ) == 1
        && EVP_EncryptUpdate(
            context,
            ciphertext.data(),
            &outputLength,
            plaintext.data(),
            plaintext.size()
        ) == 1;

    totalLength = outputLength;

    success = success
        && EVP_EncryptFinal_ex(
            context,
            ciphertext.data() + totalLength,
            &outputLength
        ) == 1;

    totalLength += outputLength;

    success = success
        && EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_GET_TAG,
            gcmTag.size(),
            gcmTag.data()
        ) == 1
        && static_cast<std::size_t>(totalLength) == plaintext.size();

    EVP_CIPHER_CTX_free(context);

    if (!success)
    {
        throw std::runtime_error("AES-GCM encryption failed");
    }

    return ciphertext;
}

static Bytes aesGcmDecrypt(
    const Bytes &ciphertext,
    const Bytes &nonce,
    const Bytes &gcmTag,
    const std::array<std::uint8_t, 16> &aad
)
{
    if (!sessionKeyAvailable)
    {
        throw std::runtime_error(
            "SCADALGERIA session is not authenticated"
        );
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();

    if (context == nullptr)
    {
        throw std::runtime_error("Unable to create AES-GCM context");
    }

    Bytes plaintext(ciphertext.size());

    int outputLength = 0;
    int totalLength = 0;

    bool success =
        EVP_DecryptInit_ex2(
            context,
            EVP_aes_256_gcm(),
            sessionKey.data(),
            nonce.data(),
            nullptr
        ) == 1
        && EVP_DecryptUpdate(
            context,
            nullptr,
            &outputLength,
            aad.data(),
            aad.size()
        ) == 1
        && EVP_DecryptUpdate(
            context,
            plaintext.data(),
            &outputLength,
            ciphertext.data(),
            ciphertext.size()
        ) == 1;

    totalLength = outputLength;

    success = success
        && EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_TAG,
            gcmTag.size(),
            const_cast<std::uint8_t *>(gcmTag.data())
        ) == 1
        && EVP_DecryptFinal_ex(
            context,
            plaintext.data() + totalLength,
            &outputLength
        ) == 1;

    EVP_CIPHER_CTX_free(context);

    if (!success)
    {
        throw std::runtime_error(
            "AES-GCM authentication failed"
        );
    }

    return plaintext;
}

static Bytes objectBinary(const msgpack::object &object)
{
    if (object.type != msgpack::type::BIN)
    {
        throw std::runtime_error("Expected MessagePack binary value");
    }

    auto *begin = reinterpret_cast<const std::uint8_t *>(
        object.via.bin.ptr
    );

    return Bytes(
        begin,
        begin + object.via.bin.size
    );
}

static std::string objectString(const msgpack::object &object)
{
    return object.as<std::string>();
}

static std::uint64_t objectUnsigned(const msgpack::object &object)
{
    return object.as<std::uint64_t>();
}

static bool objectBoolean(const msgpack::object &object)
{
    if (object.type != msgpack::type::BOOLEAN)
    {
        throw std::runtime_error("Expected MessagePack boolean value");
    }

    return object.via.boolean;
}

static int objectOutputBit(const msgpack::object &object)
{
    if (object.type == msgpack::type::BOOLEAN)
    {
        return object.via.boolean ? 1 : 0;
    }

    if (
        object.type == msgpack::type::POSITIVE_INTEGER
        && object.via.u64 <= 1
    )
    {
        return static_cast<int>(object.via.u64);
    }

    if (
        object.type == msgpack::type::FLOAT32
        || object.type == msgpack::type::FLOAT64
    )
    {
        const double value = object.via.f64;

        if (value == 0.0 || value == 1.0)
        {
            return static_cast<int>(value);
        }
    }

    throw std::runtime_error(
        "do.output1 accepts only 0 or 1"
    );
}


template <typename Writer>
static Bytes packMessage(Writer writer)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> packer(buffer);

    writer(packer);

    auto *begin = reinterpret_cast<const std::uint8_t *>(
        buffer.data()
    );

    return Bytes(
        begin,
        begin + buffer.size()
    );
}


// ============================================================================
// STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
// ============================================================================

static Bytes buildDigitalInputTelemetry(int inputValue)
{
    return packMessage(
        [&](auto &packer)
        {
            packer.pack_array(3);

            packer.pack_array(1);

            packer.pack_array(5);
            packer.pack(std::string(InputTagAddress));
            packer.pack(static_cast<double>(inputValue));
            packer.pack_nil();
            packer.pack(std::int64_t{0});
            packer.pack(192);

            packer.pack_nil();
            packer.pack(1);
        }
    );
}

static Bytes buildCommandResult(
    const std::string &commandId,
    bool success,
    const std::string &errorMessage,
    int appliedValue
)
{
    return packMessage(
        [&](auto &packer)
        {
            packer.pack_array(5);
            packer.pack(commandId);
            packer.pack(success);

            if (errorMessage.empty())
            {
                packer.pack_nil();
            }
            else
            {
                packer.pack(errorMessage);
            }

            if (success)
            {
                packer.pack(
                    std::string("{\"appliedValue\":")
                    + std::to_string(appliedValue)
                    + "}"
                );
            }
            else
            {
                packer.pack_nil();
            }

            packer.pack(1);
        }
    );
}

static Bytes encryptScadalgeriaPayload(const Bytes &innerMessage)
{
    const auto sequence = deviceState.reserveNextSequence();
    const auto timestampMs = currentUnixMilliseconds();

    std::array<std::uint8_t, 12> nonce{};

    if (RAND_bytes(nonce.data(), nonce.size()) != 1)
    {
        throw std::runtime_error("Secure random generation failed");
    }

    const auto aad = buildEnvelopeAad(
        sequence,
        timestampMs
    );

    std::array<std::uint8_t, 16> gcmTag{};

    const Bytes ciphertext = aesGcmEncrypt(
        innerMessage,
        nonce,
        aad,
        gcmTag
    );

    return packMessage(
        [&](auto &packer)
        {
            packer.pack_array(6);
            packer.pack(configuration.apiKeyId);

            packer.pack_bin(nonce.size());
            packer.pack_bin_body(
                reinterpret_cast<const char *>(nonce.data()),
                nonce.size()
            );

            packer.pack_bin(ciphertext.size());
            packer.pack_bin_body(
                reinterpret_cast<const char *>(ciphertext.data()),
                ciphertext.size()
            );

            packer.pack_bin(gcmTag.size());
            packer.pack_bin_body(
                reinterpret_cast<const char *>(gcmTag.data()),
                gcmTag.size()
            );

            packer.pack(sequence);
            packer.pack(timestampMs);
        }
    );
}

static Bytes decryptScadalgeriaPayload(const Bytes &envelopePayload)
{
    auto handle = msgpack::unpack(
        reinterpret_cast<const char *>(envelopePayload.data()),
        envelopePayload.size()
    );

    const auto &envelope = handle.get();

    if (
        envelope.type != msgpack::type::ARRAY
        || envelope.via.array.size != 6
    )
    {
        throw std::runtime_error(
            "AesGcmEnvelopeDto must contain exactly 6 fields"
        );
    }

    const auto *fields = envelope.via.array.ptr;

    const auto keyId = objectString(fields[0]);
    const auto nonce = objectBinary(fields[1]);
    const auto ciphertext = objectBinary(fields[2]);
    const auto gcmTag = objectBinary(fields[3]);
    const auto sequence = objectUnsigned(fields[4]);
    const auto timestampMs = objectUnsigned(fields[5]);

    if (keyId != configuration.apiKeyId)
    {
        throw std::runtime_error(
            "Encrypted envelope KeyId does not match this credential"
        );
    }

    if (nonce.size() != 12)
    {
        throw std::runtime_error(
            "Encrypted envelope nonce must be 12 bytes"
        );
    }

    if (gcmTag.size() != 16)
    {
        throw std::runtime_error(
            "Encrypted envelope GCM tag must be 16 bytes"
        );
    }

    return aesGcmDecrypt(
        ciphertext,
        nonce,
        gcmTag,
        buildEnvelopeAad(
            sequence,
            timestampMs
        )
    );
}


// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
// ============================================================================

static void publishRawQos1(
    mqtt::client &client,
    const std::string &topic,
    const Bytes &payload
)
{
    client.publish(
        topic,
        payload.data(),
        payload.size(),
        1,
        false
    );
}

static void publishEncryptedMessage(
    mqtt::client &client,
    const std::string &topic,
    const Bytes &innerMessage
)
{
    const Bytes encrypted = encryptScadalgeriaPayload(
        innerMessage
    );

    publishRawQos1(
        client,
        topic,
        encrypted
    );
}

static void subscribeExactQos1(
    mqtt::client &client,
    const std::string &topic
)
{
    const auto response = client.subscribe(
        topic,
        1
    );

    const auto &reasonCodes = response.get_reason_codes();

    if (
        reasonCodes.size() != 1
        || reasonCodes[0] != mqtt::ReasonCode::GRANTED_QOS_1
    )
    {
        throw std::runtime_error(
            "The broker did not grant QoS 1 subscription: " + topic
        );
    }
}

static void authenticateWithScadalgeria(
    mqtt::client &client,
    const Bytes &challengePayload
)
{
    auto handle = msgpack::unpack(
        reinterpret_cast<const char *>(challengePayload.data()),
        challengePayload.size()
    );

    const auto &challenge = handle.get();

    if (
        challenge.type != msgpack::type::ARRAY
        || challenge.via.array.size != 2
    )
    {
        throw std::runtime_error(
            "MqttAuthChallengeDto must contain exactly 2 fields"
        );
    }

    const auto *fields = challenge.via.array.ptr;

    const Bytes serverNonce = objectBinary(fields[0]);
    const auto expiresAtMs = objectUnsigned(fields[1]);

    if (serverNonce.size() != 16)
    {
        throw std::runtime_error(
            "Authentication ServerNonce must be 16 bytes"
        );
    }

    if (currentUnixMilliseconds() >= expiresAtMs)
    {
        throw std::runtime_error(
            "SCADALGERIA authentication challenge expired"
        );
    }

    std::array<std::uint8_t, 16> clientNonce{};

    if (RAND_bytes(clientNonce.data(), clientNonce.size()) != 1)
    {
        throw std::runtime_error("Secure random generation failed");
    }

    Bytes proofMessage = serverNonce;

    proofMessage.insert(
        proofMessage.end(),
        clientNonce.begin(),
        clientNonce.end()
    );

    proofMessage.insert(
        proofMessage.end(),
        configuration.clientId.begin(),
        configuration.clientId.end()
    );

    const Bytes authenticationProof = hmacSha256(
        proofMessage
    );

    deriveSessionKey(
        serverNonce,
        clientNonce
    );

    const Bytes authResponse = packMessage(
        [&](auto &packer)
        {
            packer.pack_array(2);

            packer.pack_bin(clientNonce.size());
            packer.pack_bin_body(
                reinterpret_cast<const char *>(clientNonce.data()),
                clientNonce.size()
            );

            packer.pack_bin(authenticationProof.size());
            packer.pack_bin_body(
                reinterpret_cast<const char *>(authenticationProof.data()),
                authenticationProof.size()
            );
        }
    );

    publishRawQos1(
        client,
        configuration.authResponseTopic,
        authResponse
    );

    // There is no custom AUTH_OK packet. A successful exact post-auth
    // command subscription is the promotion proof for this example.
    subscribeExactQos1(
        client,
        configuration.commandsTopic
    );

    authenticated = true;

    std::cout
        << "SCADALGERIA session authenticated; telemetry and commands are enabled"
        << std::endl;
}

static void publishDigitalInputTelemetry(
    mqtt::client &client,
    DigitalIo &io
)
{
    const int inputValue = io.readInput();

    const Bytes telemetry = buildDigitalInputTelemetry(
        inputValue
    );

    publishEncryptedMessage(
        client,
        configuration.telemetryTopic,
        telemetry
    );

    std::cout
        << "Telemetry sent: "
        << InputTagAddress
        << "="
        << inputValue
        << std::endl;
}


// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
// ============================================================================

static void handleScadalgeriaCommand(
    mqtt::client &client,
    DigitalIo &io,
    const Bytes &encryptedPayload
)
{
    const Bytes plaintext = decryptScadalgeriaPayload(
        encryptedPayload
    );

    auto handle = msgpack::unpack(
        reinterpret_cast<const char *>(plaintext.data()),
        plaintext.size()
    );

    const auto &command = handle.get();

    if (
        command.type != msgpack::type::ARRAY
        || command.via.array.size != 10
    )
    {
        throw std::runtime_error(
            "CommandDto must contain exactly 10 fields"
        );
    }

    const auto *fields = command.via.array.ptr;

    const std::string commandId = objectString(fields[0]);

    if (commandId.empty())
    {
        throw std::runtime_error(
            "Command Id must not be empty"
        );
    }

    if (auto cached = deviceState.getCommandResult(commandId))
    {
        std::cout
            << "Command redelivery detected: "
            << commandId
            << "; returning cached result"
            << std::endl;

        publishEncryptedMessage(
            client,
            configuration.commandResultTopic,
            *cached
        );

        return;
    }

    bool success = false;
    int appliedValue = 0;
    std::string errorMessage;

    try
    {
        const auto schemaVersion = objectUnsigned(fields[9]);
        const auto tagAddress = objectString(fields[1]);
        const auto expiryEpochSeconds = objectUnsigned(fields[4]);
        const auto requiresConfirmation = objectBoolean(fields[7]);
        const auto confirmed = objectBoolean(fields[8]);

        if (schemaVersion != 2)
        {
            throw std::runtime_error(
                "Unsupported CommandDto schema version"
            );
        }

        if (tagAddress != OutputTagAddress)
        {
            throw std::runtime_error(
                "Unsupported command address: " + tagAddress
            );
        }

        if (
            expiryEpochSeconds
            <= currentUnixMilliseconds() / 1000ULL
        )
        {
            throw std::runtime_error("Command expired");
        }

        if (requiresConfirmation && !confirmed)
        {
            throw std::runtime_error(
                "Command requires operator confirmation"
            );
        }

        appliedValue = objectOutputBit(fields[2]);

        io.writeOutput(appliedValue);
        success = true;

        std::cout
            << "Command applied: "
            << OutputTagAddress
            << "="
            << appliedValue
            << std::endl;
    }
    catch (const std::exception &error)
    {
        errorMessage = error.what();

        if (errorMessage.size() > 256)
        {
            errorMessage.resize(256);
        }

        std::cerr
            << "Command rejected: "
            << errorMessage
            << std::endl;
    }

    const Bytes finalResult = buildCommandResult(
        commandId,
        success,
        errorMessage,
        appliedValue
    );

    deviceState.rememberCommandResult(
        commandId,
        finalResult
    );

    publishEncryptedMessage(
        client,
        configuration.commandResultTopic,
        finalResult
    );
}


// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
// ============================================================================

static void clearAuthenticatedSession()
{
    OPENSSL_cleanse(
        sessionKey.data(),
        sessionKey.size()
    );

    sessionKeyAvailable = false;
    authenticated = false;
}

static mqtt::connect_options buildConnectOptions()
{
    return mqtt::connect_options_builder()
        .user_name(configuration.mqttUsername)
        .password("")
        .clean_session(true)
        .mqtt_version(MQTTVERSION_3_1_1)
        .finalize();
}

static void connectAndStartAuthentication(
    mqtt::client &client
)
{
    clearAuthenticatedSession();

    client.connect(
        buildConnectOptions()
    );

    subscribeExactQos1(
        client,
        configuration.authChallengeTopic
    );

    std::cout
        << "MQTT connected; waiting for a fresh SCADALGERIA challenge"
        << std::endl;
}

int main()
{
    DigitalIo io;

    const std::string brokerUri =
        "tcp://"
        + configuration.host
        + ":"
        + std::to_string(configuration.port);

    mqtt::client client(
        brokerUri,
        configuration.clientId
    );

    client.start_consuming();

    std::chrono::seconds reconnectDelay{1};
    auto lastTelemetry = std::chrono::steady_clock::now();

    for (;;)
    {
        try
        {
            if (!client.is_connected())
            {
                connectAndStartAuthentication(client);
                reconnectDelay = 1s;
            }

            mqtt::const_message_ptr message;

            if (
                client.try_consume_message_for(
                    &message,
                    100ms
                )
                && message
            )
            {
                const auto &payloadString = message->get_payload();

                Bytes payload(
                    reinterpret_cast<const std::uint8_t *>(payloadString.data()),
                    reinterpret_cast<const std::uint8_t *>(payloadString.data())
                        + payloadString.size()
                );

                if (message->get_topic() == configuration.authChallengeTopic)
                {
                    authenticateWithScadalgeria(
                        client,
                        payload
                    );
                }
                else if (
                    authenticated
                    && message->get_topic() == configuration.commandsTopic
                )
                {
                    handleScadalgeriaCommand(
                        client,
                        io,
                        payload
                    );
                }
            }

            const auto now = std::chrono::steady_clock::now();

            if (
                authenticated
                && now - lastTelemetry >= 1s
            )
            {
                publishDigitalInputTelemetry(
                    client,
                    io
                );

                lastTelemetry = now;

                // Also obey the copied configuration telemetryPolicy.
            }
        }
        catch (const mqtt::exception &error)
        {
            clearAuthenticatedSession();

            std::cerr
                << "MQTT error: "
                << error.what()
                << "; reconnecting with backoff"
                << std::endl;

            try
            {
                if (client.is_connected())
                {
                    client.disconnect();
                }
            }
            catch (...)
            {
            }

            std::this_thread::sleep_for(reconnectDelay);

            reconnectDelay = std::min(
                reconnectDelay * 2,
                30s
            );
        }
        catch (const std::exception &error)
        {
            std::cerr
                << "SCADALGERIA protocol error: "
                << error.what()
                << std::endl;
        }
    }
}
