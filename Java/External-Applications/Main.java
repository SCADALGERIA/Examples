/**
 * SCADALGERIA Direct Firmware example — Raspberry Pi 5 / Java
 *
 * The example demonstrates one complete Direct Firmware integration:
 *
 *   BCM17 -> "di.input1" telemetry -> SCADALGERIA
 *   BCM27 <- "do.output1" command  <- SCADALGERIA
 *
 * The code intentionally keeps the protocol visible. It uses ordinary Paho,
 * MessagePack, JCA/JCE, and Pi4J APIs instead of hiding the wire contract
 * behind a made-up SCADALGERIA SDK.
 */


// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

import com.pi4j.Pi4J;
import com.pi4j.context.Context;
import com.pi4j.io.gpio.digital.DigitalInput;
import com.pi4j.io.gpio.digital.DigitalOutput;
import com.pi4j.io.gpio.digital.DigitalState;
import com.pi4j.io.gpio.digital.PullResistance;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;

import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.Value;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;


public final class Main {

    // ========================================================================
    // ========================================================================
    // STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
    //
    // Save Connection → Copy firmware configuration → Copy JSON as
    // `scadalgeria-connection.json`. Supply SCADALGERIA_API_KEY separately.
    // ========================================================================

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String INPUT_TAG_ADDRESS = "di.input1";
    private static final String OUTPUT_TAG_ADDRESS = "do.output1";

    private record ConnectionConfiguration(
        String host,
        int port,
        String clientId,
        String mqttUsername,
        String apiKeyId,
        String apiKeyToken,
        String authChallengeTopic,
        String authResponseTopic,
        String telemetryTopic,
        String commandsTopic,
        String commandResultTopic
    ) {}

    private static String requiredSecret(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Missing required secret: " + name);
        return value;
    }

    private static JsonNode requiredObject(JsonNode parent, String name) {
        JsonNode value = parent.get(name);
        if (value == null || !value.isObject()) throw new IllegalStateException("Copied configuration field '" + name + "' must be an object");
        return value;
    }

    private static String requiredString(JsonNode parent, String name) {
        JsonNode value = parent.get(name);
        if (value == null || !value.isTextual() || value.asText().isBlank()) throw new IllegalStateException("Copied configuration field '" + name + "' is missing or invalid");
        return value.asText();
    }

    private static String createUniqueClientId() {
        byte[] random = new byte[8];
        RANDOM.nextBytes(random);
        return "scada-" + java.util.HexFormat.of().formatHex(random);
    }

    private static String resolveClientTopic(String template, String clientId) {
        int first = template.indexOf("{clientId}");
        int second = first < 0 ? -1 : template.indexOf("{clientId}", first + 10);
        if (first < 0 || second >= 0) throw new IllegalStateException("Authentication topic template must contain exactly one {clientId}");
        return template.substring(0, first) + clientId + template.substring(first + 10);
    }

    private static void requireBooleanTag(JsonNode root, String address, String direction) {
        JsonNode tags = root.get("tags");
        if (tags == null || !tags.isArray()) throw new IllegalStateException("Copied configuration has no tags array");
        int count = 0;
        for (JsonNode tag : tags) {
            if (address.equals(requiredString(tag, "address"))) {
                count++;
                if (!"Boolean".equals(requiredString(tag, "dataType")) || !direction.equals(requiredString(tag, "direction")))
                    throw new IllegalStateException("Tag '" + address + "' must be Boolean/" + direction);
            }
        }
        if (count != 1) throw new IllegalStateException("Copied configuration must contain exactly one tag '" + address + "'");
    }

    private static ConnectionConfiguration loadConnectionConfiguration() {
        try {
            String path = System.getenv().getOrDefault("SCADALGERIA_CONFIG_FILE", "scadalgeria-connection.json");
            JsonNode root = JSON.readTree(Files.readString(Path.of(path)));

            if (!"scadalgeria.direct-firmware.connection".equals(requiredString(root, "schema")) || root.path("schemaVersion").asInt(-1) != 1)
                throw new IllegalStateException("Unsupported SCADALGERIA connection configuration schema");

            JsonNode connection = requiredObject(root, "connection");
            JsonNode identity = requiredObject(root, "identity");
            JsonNode mqtt = requiredObject(root, "mqtt");
            JsonNode broker = requiredObject(mqtt, "broker");
            JsonNode topics = requiredObject(mqtt, "topics");
            JsonNode qos = requiredObject(mqtt, "qos");
            JsonNode authentication = requiredObject(root, "authentication");
            JsonNode encryption = requiredObject(root, "encryption");
            JsonNode kdf = requiredObject(encryption, "sessionKeyDerivation");
            JsonNode secrets = requiredObject(root, "secrets");

            if (!connection.path("enabled").asBoolean(false)) throw new IllegalStateException("The copied Connection is disabled");
            if (!"3.1.1".equals(requiredString(mqtt, "protocol")) || !mqtt.path("cleanSession").asBoolean(false)) throw new IllegalStateException("MQTT 3.1.1 with cleanSession=true is required");
            if (!"tcp".equals(requiredString(broker, "transport"))) throw new IllegalStateException("Unsupported copied MQTT transport");
            if (!"unique-per-active-session".equals(requiredString(mqtt, "clientIdRequirement"))) throw new IllegalStateException("Unsupported clientIdRequirement");
            if (qos.path("telemetry").asInt(-1) != 1 || qos.path("commands").asInt(-1) != 1 || qos.path("commandResults").asInt(-1) != 1) throw new IllegalStateException("Copied telemetry/command/result QoS must be 1");
            if (!"HMAC-SHA256".equals(requiredString(authentication, "scheme")) || !"AES-256-GCM".equals(requiredString(encryption, "scheme"))) throw new IllegalStateException("Unsupported authentication/encryption contract");
            if (!"HKDF-SHA256".equals(requiredString(kdf, "algorithm")) || !"SCADA-ENC-v1".equals(requiredString(kdf, "info"))) throw new IllegalStateException("Unsupported session-key derivation contract");
            if (secrets.path("apiKeySecretIncluded").asBoolean(true)) throw new IllegalStateException("Connection Copy JSON must never contain the API-key secret");

            requireBooleanTag(root, INPUT_TAG_ADDRESS, "Input");
            requireBooleanTag(root, OUTPUT_TAG_ADDRESS, "Output");

            String clientId = createUniqueClientId();
            return new ConnectionConfiguration(
                requiredString(broker, "host"),
                broker.path("port").asInt(),
                clientId,
                requiredString(mqtt, "username"),
                requiredString(identity, "keyId"),
                requiredSecret("SCADALGERIA_API_KEY"),
                resolveClientTopic(requiredString(topics, "authenticationChallenge"), clientId),
                resolveClientTopic(requiredString(topics, "authenticationResponse"), clientId),
                requiredString(topics, "telemetry"),
                requiredString(topics, "commands"),
                requiredString(topics, "commandResults")
            );
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("Unable to read copied SCADALGERIA connection configuration", ex);
        }
    }

    private static final ConnectionConfiguration CONFIG = loadConnectionConfiguration();
    private static final String MQTT_HOST = CONFIG.host();
    private static final int MQTT_PORT = CONFIG.port();
    private static final String CLIENT_ID = CONFIG.clientId();
    private static final String MQTT_USERNAME = CONFIG.mqttUsername();
    private static final String API_KEY_ID = CONFIG.apiKeyId();
    private static final String API_KEY_TOKEN = CONFIG.apiKeyToken();
    private static final String AUTH_CHALLENGE_TOPIC = CONFIG.authChallengeTopic();
    private static final String AUTH_RESPONSE_TOPIC = CONFIG.authResponseTopic();
    private static final String TELEMETRY_TOPIC = CONFIG.telemetryTopic();
    private static final String COMMAND_TOPIC = CONFIG.commandsTopic();
    private static final String COMMAND_RESULT_TOPIC = CONFIG.commandResultTopic();


    // ========================================================================
    //
    // STEP 3 OF 9 — LOCAL DIGITAL I/O
    //
    // BCM17 is an active-low switch input with a pull-up.
    // BCM27 is the set-state digital output.
    //
    // Never connect an industrial load directly to a Raspberry Pi GPIO.
    // Use appropriate isolation/driver hardware outside this snippet.
    // ========================================================================

    private static Context pi4j;
    private static DigitalInput digitalInput;
    private static DigitalOutput digitalOutput;

    private static void initializeDigitalIo() {
        pi4j = Pi4J.newAutoContext();

        digitalInput = pi4j.create(
            DigitalInput.newConfigBuilder(pi4j)
                .id("scada-di-input1")
                .name(INPUT_TAG_ADDRESS)
                .address(17)
                .pull(PullResistance.PULL_UP)
                .build()
        );

        digitalOutput = pi4j.create(
            DigitalOutput.newConfigBuilder(pi4j)
                .id("scada-do-output1")
                .name(OUTPUT_TAG_ADDRESS)
                .address(27)
                .initial(DigitalState.LOW)
                .shutdown(DigitalState.LOW)
                .build()
        );
    }

    private static int readDigitalInput() {
        return digitalInput.state() == DigitalState.LOW
            ? 1
            : 0;
    }

    private static void writeDigitalOutput(int value) {
        digitalOutput.state(
            value == 1
                ? DigitalState.HIGH
                : DigitalState.LOW
        );
    }


    // ========================================================================
    // STEP 4 OF 9 — DURABLE DEVICE STATE
    //
    // The outgoing envelope Seq is durable replay/order state. It survives:
    //
    //   MQTT reconnects
    //   process restarts
    //   host reboot/power loss
    //
    // The example writes the incremented Seq before returning it. Skipping a
    // value after a crash is safe; reusing a value is not.
    //
    // Command results are cached by CommandDto.Id to handle normal at-least-
    // once redelivery without applying the same set-state output twice.
    // ========================================================================

    private static final DeviceStateStore STATE =
        new DeviceStateStore(
            Path.of(".scadalgeria-state.properties")
        );


    // ========================================================================
    // STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
    //
    // CONNECT is only transport admission. SCADALGERIA session promotion is:
    //
    //   subscribe authChallenge
    //       ↓
    //   receive [ServerNonce, ExpiresAtUnixMs]
    //       ↓
    //   ClientNonce = SecureRandom(16)
    //       ↓
    //   HMAC-SHA256(ServerNonce || ClientNonce || UTF8(ClientId))
    //       ↓
    //   publish [ClientNonce, Auth]
    //       ↓
    //   derive 32-byte HKDF-SHA256 session key
    //       ↓
    //   subscribe exact commands topic
    //
    // Every reconnect discards the old session key and repeats this sequence.
    // ========================================================================

    private static final Object SESSION_LOCK = new Object();

    private static byte[] sessionKey;
    private static volatile boolean authenticated;

    private static MqttClient mqttClient;

    private static long currentUnixMilliseconds() {
        return Instant.now().toEpochMilli();
    }

    private static long currentUnixSeconds() {
        return Instant.now().getEpochSecond();
    }

    private static void setSessionKey(byte[] newKey) {
        synchronized (SESSION_LOCK) {
            sessionKey = Arrays.copyOf(
                newKey,
                newKey.length
            );
        }
    }

    private static byte[] requireSessionKey() {
        synchronized (SESSION_LOCK) {
            if (sessionKey == null) {
                throw new IllegalStateException(
                    "SCADALGERIA session is not authenticated"
                );
            }

            return Arrays.copyOf(
                sessionKey,
                sessionKey.length
            );
        }
    }

    private static void clearAuthenticatedSession() {
        synchronized (SESSION_LOCK) {
            sessionKey = null;
        }

        authenticated = false;
    }

    private static byte[] hmacSha256(
        byte[] key,
        byte[] message
    ) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(
            new SecretKeySpec(
                key,
                "HmacSHA256"
            )
        );

        return mac.doFinal(message);
    }

    private static byte[] deriveSessionKey(
        byte[] serverNonce,
        byte[] clientNonce
    ) throws Exception {
        // RFC 5869 HKDF with SHA-256.
        // We need exactly one 32-byte expansion block.
        byte[] tokenBytes = API_KEY_TOKEN.getBytes(
            StandardCharsets.UTF_8
        );

        byte[] salt = concatenate(
            serverNonce,
            clientNonce
        );

        byte[] pseudoRandomKey = hmacSha256(
            salt,
            tokenBytes
        );

        byte[] info = "SCADA-ENC-v1".getBytes(
            StandardCharsets.UTF_8
        );

        byte[] expandInput = Arrays.copyOf(
            info,
            info.length + 1
        );

        // HKDF block counter T(1).
        expandInput[expandInput.length - 1] = 1;

        return hmacSha256(
            pseudoRandomKey,
            expandInput
        );
    }

    private static byte[] buildAuthenticationProof(
        byte[] serverNonce,
        byte[] clientNonce
    ) throws Exception {
        byte[] proofMessage = concatenate(
            serverNonce,
            clientNonce,
            CLIENT_ID.getBytes(StandardCharsets.UTF_8)
        );

        return hmacSha256(
            API_KEY_TOKEN.getBytes(StandardCharsets.UTF_8),
            proofMessage
        );
    }

    private static void authenticateWithScadalgeria(
        byte[] challengePayload
    ) throws Exception {
        byte[] serverNonce;
        long expiresAtUnixMs;

        try (MessageUnpacker unpacker =
                 MessagePack.newDefaultUnpacker(challengePayload)) {

            int fieldCount = unpacker.unpackArrayHeader();

            if (fieldCount != 2) {
                throw new SecurityException(
                    "MqttAuthChallengeDto must contain exactly 2 fields"
                );
            }

            int nonceLength = unpacker.unpackBinaryHeader();
            serverNonce = unpacker.readPayload(nonceLength);

            expiresAtUnixMs = unpacker.unpackLong();
        }

        if (serverNonce.length != 16) {
            throw new SecurityException(
                "Authentication ServerNonce must be 16 bytes"
            );
        }

        if (currentUnixMilliseconds() >= expiresAtUnixMs) {
            throw new SecurityException(
                "SCADALGERIA authentication challenge expired"
            );
        }

        byte[] clientNonce = new byte[16];
        RANDOM.nextBytes(clientNonce);

        byte[] authenticationProof = buildAuthenticationProof(
            serverNonce,
            clientNonce
        );

        byte[] newSessionKey = deriveSessionKey(
            serverNonce,
            clientNonce
        );

        byte[] authResponse;

        try (MessageBufferPacker packer =
                 MessagePack.newDefaultBufferPacker()) {

            // MqttAuthResponseDto:
            //
            //   [0] ClientNonce byte[16]
            //   [1] Auth        byte[32]
            packer.packArrayHeader(2);

            packer.packBinaryHeader(clientNonce.length);
            packer.writePayload(clientNonce);

            packer.packBinaryHeader(authenticationProof.length);
            packer.writePayload(authenticationProof);

            authResponse = packer.toByteArray();
        }

        setSessionKey(newSessionKey);

        mqttClient.publish(
            AUTH_RESPONSE_TOPIC,
            authResponse,
            1,
            false
        );

        // There is no separate custom AUTH_OK packet. For this bidirectional
        // example, a successful exact post-auth command subscription is the
        // promotion gate.
        IMqttToken commandSubscription = mqttClient.subscribeWithResponse(
            COMMAND_TOPIC,
            1
        );

        int[] grantedCommandQos = commandSubscription.getGrantedQos();

        if (
            grantedCommandQos.length != 1
            || grantedCommandQos[0] != 1
        ) {
            clearAuthenticatedSession();

            throw new SecurityException(
                "The broker did not grant the exact command subscription at QoS 1"
            );
        }

        authenticated = true;

        System.out.println(
            "SCADALGERIA session authenticated; telemetry and commands are enabled"
        );
    }


    // ========================================================================
    // STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
    //
    // AesGcmEnvelopeDto:
    //
    //   [ KeyId, Nonce, Ciphertext, GcmTag, Seq, TsUnixMs ]
    //
    // Nonce: 12 fresh random bytes per envelope.
    // GCM tag: 16 bytes.
    // AAD: UInt64BE(Seq) || UInt64BE(TsUnixMs).
    // ========================================================================

    private static byte[] buildEnvelopeAad(
        long sequence,
        long timestampMs
    ) {
        return ByteBuffer
            .allocate(16)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(sequence)
            .putLong(timestampMs)
            .array();
    }

    private static byte[] encryptScadalgeriaPayload(
        byte[] innerMessage
    ) throws Exception {
        byte[] encryptionKey = requireSessionKey();

        long sequence = STATE.reserveNextSequence();
        long timestampMs = currentUnixMilliseconds();

        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(
            "AES/GCM/NoPadding"
        );

        cipher.init(
            Cipher.ENCRYPT_MODE,
            new SecretKeySpec(
                encryptionKey,
                "AES"
            ),
            new GCMParameterSpec(
                128,
                nonce
            )
        );

        cipher.updateAAD(
            buildEnvelopeAad(
                sequence,
                timestampMs
            )
        );

        byte[] ciphertextAndTag = cipher.doFinal(
            innerMessage
        );

        int ciphertextLength = ciphertextAndTag.length - 16;

        byte[] ciphertext = Arrays.copyOf(
            ciphertextAndTag,
            ciphertextLength
        );

        byte[] gcmTag = Arrays.copyOfRange(
            ciphertextAndTag,
            ciphertextLength,
            ciphertextAndTag.length
        );

        try (MessageBufferPacker packer =
                 MessagePack.newDefaultBufferPacker()) {

            packer.packArrayHeader(6);
            packer.packString(API_KEY_ID);

            packer.packBinaryHeader(nonce.length);
            packer.writePayload(nonce);

            packer.packBinaryHeader(ciphertext.length);
            packer.writePayload(ciphertext);

            packer.packBinaryHeader(gcmTag.length);
            packer.writePayload(gcmTag);

            packer.packLong(sequence);
            packer.packLong(timestampMs);

            return packer.toByteArray();
        }
    }

    private static byte[] decryptScadalgeriaPayload(
        byte[] envelopePayload
    ) throws Exception {
        String keyId;
        byte[] nonce;
        byte[] ciphertext;
        byte[] gcmTag;
        long sequence;
        long timestampMs;

        try (MessageUnpacker unpacker =
                 MessagePack.newDefaultUnpacker(envelopePayload)) {

            if (unpacker.unpackArrayHeader() != 6) {
                throw new SecurityException(
                    "AesGcmEnvelopeDto must contain exactly 6 fields"
                );
            }

            keyId = unpacker.unpackString();

            nonce = unpacker.readPayload(
                unpacker.unpackBinaryHeader()
            );

            ciphertext = unpacker.readPayload(
                unpacker.unpackBinaryHeader()
            );

            gcmTag = unpacker.readPayload(
                unpacker.unpackBinaryHeader()
            );

            sequence = unpacker.unpackLong();
            timestampMs = unpacker.unpackLong();
        }

        if (!API_KEY_ID.equals(keyId)) {
            throw new SecurityException(
                "Encrypted envelope KeyId does not match this credential"
            );
        }

        if (nonce.length != 12) {
            throw new SecurityException(
                "Encrypted envelope nonce must be 12 bytes"
            );
        }

        if (gcmTag.length != 16) {
            throw new SecurityException(
                "Encrypted envelope GCM tag must be 16 bytes"
            );
        }

        Cipher cipher = Cipher.getInstance(
            "AES/GCM/NoPadding"
        );

        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(
                requireSessionKey(),
                "AES"
            ),
            new GCMParameterSpec(
                128,
                nonce
            )
        );

        cipher.updateAAD(
            buildEnvelopeAad(
                sequence,
                timestampMs
            )
        );

        return cipher.doFinal(
            concatenate(
                ciphertext,
                gcmTag
            )
        );
    }

    private static void publishEncryptedMessage(
        String topic,
        byte[] innerMessage
    ) throws Exception {
        byte[] encryptedPayload = encryptScadalgeriaPayload(
            innerMessage
        );

        mqttClient.publish(
            topic,
            encryptedPayload,
            1,
            false
        );
    }


    // ========================================================================
    // STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
    //
    // TagFrameDto:
    //
    //   [ "di.input1", ValNum, null, 0, 192 ]
    //
    // TagFrameBatchDto:
    //
    //   [ [TagFrameDto], null, 1 ]
    // ========================================================================

    private static byte[] buildDigitalInputTelemetry(
        int inputValue
    ) throws Exception {
        try (MessageBufferPacker packer =
                 MessagePack.newDefaultBufferPacker()) {

            packer.packArrayHeader(3);

            // Frames
            packer.packArrayHeader(1);

            // TagFrameDto
            packer.packArrayHeader(5);
            packer.packString(INPUT_TAG_ADDRESS);
            packer.packDouble(inputValue);
            packer.packNil();
            packer.packLong(0);
            packer.packInt(192);

            // TraceId
            packer.packNil();

            // SchemaVersion
            packer.packInt(1);

            return packer.toByteArray();
        }
    }

    private static void publishDigitalInputTelemetry()
        throws Exception {

        int inputValue = readDigitalInput();

        publishEncryptedMessage(
            TELEMETRY_TOPIC,
            buildDigitalInputTelemetry(inputValue)
        );

        System.out.println(
            "Telemetry sent: "
            + INPUT_TAG_ADDRESS
            + "="
            + inputValue
        );
    }


    // ========================================================================
    // STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
    // ========================================================================

    private static int parseOutputBit(Value value) {
        if (value.isBooleanValue()) {
            return value
                .asBooleanValue()
                .getBoolean()
                ? 1
                : 0;
        }

        if (value.isIntegerValue()) {
            int integer = value
                .asIntegerValue()
                .toInt();

            if (integer == 0 || integer == 1) {
                return integer;
            }
        }

        throw new IllegalArgumentException(
            "do.output1 accepts only 0 or 1"
        );
    }

    private static byte[] buildCommandResult(
        String commandId,
        boolean success,
        String errorMessage,
        String data
    ) throws Exception {
        try (MessageBufferPacker packer =
                 MessagePack.newDefaultBufferPacker()) {

            packer.packArrayHeader(5);
            packer.packString(commandId);
            packer.packBoolean(success);

            if (errorMessage == null) {
                packer.packNil();
            } else {
                String boundedError = errorMessage.substring(
                    0,
                    Math.min(256, errorMessage.length())
                );

                packer.packString(boundedError);
            }

            if (data == null) {
                packer.packNil();
            } else {
                packer.packString(data);
            }

            packer.packInt(1);

            return packer.toByteArray();
        }
    }

    private static void handleScadalgeriaCommand(
        byte[] encryptedPayload
    ) {
        try {
            byte[] plaintext = decryptScadalgeriaPayload(
                encryptedPayload
            );

            String commandId;
            String tagAddress;
            Value commandValue;
            long expiryEpochSeconds;
            boolean requiresConfirmation;
            boolean confirmed;
            int schemaVersion;

            try (MessageUnpacker unpacker =
                     MessagePack.newDefaultUnpacker(plaintext)) {

                if (unpacker.unpackArrayHeader() != 10) {
                    throw new IllegalArgumentException(
                        "CommandDto must contain exactly 10 fields"
                    );
                }

                commandId = unpacker.unpackString();
                tagAddress = unpacker.unpackString();
                commandValue = unpacker.unpackValue();

                // Timestamp is not used by this small GPIO example.
                unpacker.skipValue();

                expiryEpochSeconds = unpacker.unpackLong();

                // LeasedUntil and TraceId are not used by this small example.
                unpacker.skipValue();
                unpacker.skipValue();

                requiresConfirmation = unpacker.unpackBoolean();
                confirmed = unpacker.unpackBoolean();
                schemaVersion = unpacker.unpackInt();
            }

            if (commandId.isBlank()) {
                throw new IllegalArgumentException(
                    "Command Id must not be empty"
                );
            }

            byte[] cachedResult = STATE.getCommandResult(
                commandId
            );

            if (cachedResult != null) {
                System.out.println(
                    "Command redelivery detected: "
                    + commandId
                    + "; returning cached result"
                );

                publishEncryptedMessage(
                    COMMAND_RESULT_TOPIC,
                    cachedResult
                );

                return;
            }

            byte[] finalResult;

            try {
                if (schemaVersion != 2) {
                    throw new IllegalArgumentException(
                        "Unsupported CommandDto schema version: "
                        + schemaVersion
                    );
                }

                if (!OUTPUT_TAG_ADDRESS.equals(tagAddress)) {
                    throw new IllegalArgumentException(
                        "Unsupported command address: "
                        + tagAddress
                    );
                }

                if (expiryEpochSeconds <= currentUnixSeconds()) {
                    throw new IllegalArgumentException(
                        "Command expired"
                    );
                }

                if (requiresConfirmation && !confirmed) {
                    throw new IllegalArgumentException(
                        "Command requires operator confirmation"
                    );
                }

                int outputValue = parseOutputBit(
                    commandValue
                );

                writeDigitalOutput(
                    outputValue
                );

                String resultData =
                    "{\"appliedValue\":"
                    + outputValue
                    + "}";

                finalResult = buildCommandResult(
                    commandId,
                    true,
                    null,
                    resultData
                );

                System.out.println(
                    "Command applied: "
                    + OUTPUT_TAG_ADDRESS
                    + "="
                    + outputValue
                );

            } catch (Exception commandError) {
                finalResult = buildCommandResult(
                    commandId,
                    false,
                    commandError.getMessage(),
                    null
                );

                System.err.println(
                    "Command rejected: "
                    + commandError.getMessage()
                );
            }

            STATE.rememberCommandResult(
                commandId,
                finalResult
            );

            publishEncryptedMessage(
                COMMAND_RESULT_TOPIC,
                finalResult
            );

        } catch (Exception protocolError) {
            System.err.println(
                "SCADALGERIA protocol error: "
                + protocolError.getMessage()
            );
        }
    }


    // ========================================================================
    // STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
    //
    // Paho is forced to MQTT 3.1.1 and CleanSession=true.
    // Automatic reconnect is enabled, but every connectComplete callback clears
    // the old app-layer session and starts again from authChallenge.
    // ========================================================================

    private static void subscribeForAuthentication()
        throws Exception {

        clearAuthenticatedSession();

        IMqttToken challengeSubscription = mqttClient.subscribeWithResponse(
            AUTH_CHALLENGE_TOPIC,
            1,
            (topic, message) -> {
                try {
                    authenticateWithScadalgeria(
                        message.getPayload()
                    );
                } catch (Exception error) {
                    System.err.println(
                        "Authentication failed: "
                        + error.getMessage()
                    );

                    clearAuthenticatedSession();
                }
            }
        );

        int[] grantedChallengeQos = challengeSubscription.getGrantedQos();

        if (
            grantedChallengeQos.length != 1
            || grantedChallengeQos[0] != 1
        ) {
            throw new SecurityException(
                "Auth challenge subscription was not granted at QoS 1"
            );
        }

        System.out.println(
            "MQTT connected; waiting for a fresh SCADALGERIA challenge"
        );
    }

    public static void main(String[] args)
        throws Exception {

        initializeDigitalIo();

        String brokerUri =
            "tcp://"
            + MQTT_HOST
            + ":"
            + MQTT_PORT;

        mqttClient = new MqttClient(
            brokerUri,
            CLIENT_ID
        );

        mqttClient.setCallback(
            new MqttCallbackExtended() {
                @Override
                public void connectComplete(
                    boolean reconnect,
                    String serverURI
                ) {
                    try {
                        subscribeForAuthentication();
                    } catch (Exception error) {
                        System.err.println(
                            "Unable to start authentication: "
                            + error.getMessage()
                        );
                    }
                }

                @Override
                public void connectionLost(Throwable cause) {
                    clearAuthenticatedSession();

                    System.err.println(
                        "MQTT connection lost; the next connection must re-authenticate"
                    );
                }

                @Override
                public void messageArrived(
                    String topic,
                    MqttMessage message
                ) {
                    if (
                        COMMAND_TOPIC.equals(topic)
                        && authenticated
                    ) {
                        handleScadalgeriaCommand(
                            message.getPayload()
                        );
                    }
                }

                @Override
                public void deliveryComplete(
                    IMqttDeliveryToken token
                ) {
                    // No application action is required here.
                    // PUBACK is transport progress, not semantic platform acceptance.
                }
            }
        );

        MqttConnectOptions connectOptions =
            new MqttConnectOptions();

        connectOptions.setMqttVersion(
            MqttConnectOptions.MQTT_VERSION_3_1_1
        );

        connectOptions.setCleanSession(true);
        connectOptions.setAutomaticReconnect(true);
        connectOptions.setUserName(MQTT_USERNAME);

        // The Direct Firmware API token is not an MQTT password.
        connectOptions.setPassword(new char[0]);

        mqttClient.connect(connectOptions);

        long authenticationDeadline =
            System.currentTimeMillis()
            + 20_000L;

        while (
            !authenticated
            && System.currentTimeMillis() < authenticationDeadline
        ) {
            Thread.sleep(25L);
        }

        if (!authenticated) {
            throw new IllegalStateException(
                "SCADALGERIA authentication was not promoted within 20 seconds"
            );
        }

        while (true) {
            if (!authenticated) {
                Thread.sleep(250L);
                continue;
            }

            publishDigitalInputTelemetry();

            // One second is only the example cadence. The production client
            // must obey the copied configuration telemetryPolicy.
            Thread.sleep(1_000L);
        }
    }


    // ========================================================================
    // SMALL SUPPORT HELPERS
    // ========================================================================

    private static byte[] concatenate(byte[]... arrays) {
        int totalLength = 0;

        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] result = new byte[totalLength];
        int offset = 0;

        for (byte[] array : arrays) {
            System.arraycopy(
                array,
                0,
                result,
                offset,
                array.length
            );

            offset += array.length;
        }

        return result;
    }

    private static final class DeviceStateStore {
        private final Path path;
        private final Properties properties = new Properties();

        DeviceStateStore(Path path) {
            this.path = path;

            try {
                if (Files.exists(path)) {
                    try (InputStream inputStream = Files.newInputStream(path)) {
                        properties.load(inputStream);
                    }
                }
            } catch (Exception error) {
                throw new RuntimeException(
                    "Unable to load durable SCADALGERIA state",
                    error
                );
            }
        }

        synchronized long reserveNextSequence() {
            long current = Long.parseUnsignedLong(
                properties.getProperty(
                    "seq",
                    "0"
                )
            );

            long next = current + 1;

            properties.setProperty(
                "seq",
                Long.toUnsignedString(next)
            );

            save();

            return next;
        }

        synchronized byte[] getCommandResult(String commandId)
            throws Exception {

            String encoded = properties.getProperty(
                commandResultKey(commandId)
            );

            if (encoded == null) {
                return null;
            }

            return Base64
                .getDecoder()
                .decode(encoded);
        }

        synchronized void rememberCommandResult(
            String commandId,
            byte[] commandResult
        ) throws Exception {

            properties.setProperty(
                commandResultKey(commandId),
                Base64
                    .getEncoder()
                    .encodeToString(commandResult)
            );

            long resultCount = properties
                .stringPropertyNames()
                .stream()
                .filter(name -> name.startsWith("result."))
                .count();

            if (resultCount > 64) {
                properties
                    .stringPropertyNames()
                    .stream()
                    .filter(name -> name.startsWith("result."))
                    .findFirst()
                    .ifPresent(properties::remove);
            }

            save();
        }

        private String commandResultKey(String commandId)
            throws Exception {

            byte[] digest = MessageDigest
                .getInstance("SHA-256")
                .digest(
                    commandId.getBytes(StandardCharsets.UTF_8)
                );

            return "result."
                + Base64
                    .getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(digest);
        }

        private void save() {
            try {
                Path temporaryPath = Path.of(
                    path.toString() + ".tmp"
                );

                try (OutputStream outputStream =
                         Files.newOutputStream(temporaryPath)) {

                    properties.store(
                        outputStream,
                        "SCADALGERIA durable device state"
                    );
                }

                try {
                    Files.move(
                        temporaryPath,
                        path,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                    );
                } catch (Exception atomicMoveNotSupported) {
                    Files.move(
                        temporaryPath,
                        path,
                        StandardCopyOption.REPLACE_EXISTING
                    );
                }

            } catch (Exception error) {
                throw new RuntimeException(
                    "Unable to persist SCADALGERIA durable state",
                    error
                );
            }
        }
    }
}
