/**
 * SCADALGERIA Direct Firmware example — Raspberry Pi 5 / TypeScript
 *
 * Complete device-side flow:
 *
 *   1. Load the Connection Copy JSON and the separately supplied API key.
 *   2. Connect with MQTT 3.1.1 and CleanSession=true.
 *   3. Complete the HMAC challenge/response.
 *   4. Derive the per-session AES-256-GCM key.
 *   5. Read BCM17 and publish "di.input1" telemetry.
 *   6. Receive and decrypt "do.output1" commands.
 *   7. Validate + deduplicate before writing BCM27.
 *   8. Publish an encrypted CommandResultDto.
 *   9. Re-authenticate after every reconnect without resetting Seq.
 *
 * This file is deliberately written as a readable protocol example. It is not
 * a complete deployment unit and does not include service management, OTA,
 * secret enrollment, watchdogs, or production observability plumbing.
 */


// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
//
// mqtt              MQTT 3.1.1 transport
// @msgpack/msgpack  SCADALGERIA positional MessagePack DTOs
// node:crypto       HMAC-SHA256, HKDF-SHA256, AES-256-GCM, CSPRNG
// rpi-io            Raspberry Pi GPIO character-device access
// node:fs           durable replay sequence + command-result cache
// ============================================================================

import fs from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
} from "node:crypto";

import mqtt from "mqtt";
import { decode, encode } from "@msgpack/msgpack";
import { RIO } from "rpi-io";


// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
//
// Save Connection → Copy firmware configuration → Copy JSON as
// `scadalgeria-connection.json`. The file is non-secret. Supply the API-key
// secret separately through SCADALGERIA_API_KEY.
// ============================================================================

type JsonObject = Record<string, unknown>;

const CONNECTION_CONFIG_FILE =
  process.env.SCADALGERIA_CONFIG_FILE ?? "scadalgeria-connection.json";

const INPUT_TAG_ADDRESS = "di.input1";
const OUTPUT_TAG_ADDRESS = "do.output1";

function requiredSecret(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required secret: ${name}`);
  return value;
}

function requireObject(value: unknown, name: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Copied configuration field '${name}' must be an object`);
  }
  return value as JsonObject;
}

function requireString(object: JsonObject, name: string): string {
  const value = object[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Copied configuration field '${name}' is missing or invalid`);
  }
  return value;
}

function requireBooleanTag(manifest: JsonObject, address: string, direction: string): void {
  const tags = Array.isArray(manifest.tags) ? manifest.tags : [];
  const matches = tags.filter((tag) => {
    const item = requireObject(tag, "tags[]");
    return item.address === address;
  }).map((tag) => requireObject(tag, "tags[]"));

  if (matches.length !== 1 || matches[0].dataType !== "Boolean" || matches[0].direction !== direction) {
    throw new Error(`Tag '${address}' must exist exactly once as Boolean/${direction}`);
  }
}

function createUniqueClientId(): string {
  return `scada-${randomBytes(8).toString("hex")}`;
}

function resolveClientTopic(template: string, clientId: string): string {
  if ((template.match(/\{clientId\}/g) ?? []).length !== 1) {
    throw new Error("Authentication topic template must contain exactly one {clientId}");
  }
  return template.replace("{clientId}", clientId);
}

function loadConnectionConfiguration() {
  const manifest = requireObject(
    JSON.parse(fs.readFileSync(CONNECTION_CONFIG_FILE, "utf8")),
    "root",
  );

  if (manifest.schema !== "scadalgeria.direct-firmware.connection" || manifest.schemaVersion !== 1) {
    throw new Error("Unsupported SCADALGERIA connection configuration schema");
  }

  const connection = requireObject(manifest.connection, "connection");
  const identity = requireObject(manifest.identity, "identity");
  const mqttConfig = requireObject(manifest.mqtt, "mqtt");
  const broker = requireObject(mqttConfig.broker, "mqtt.broker");
  const topics = requireObject(mqttConfig.topics, "mqtt.topics");
  const qos = requireObject(mqttConfig.qos, "mqtt.qos");
  const authentication = requireObject(manifest.authentication, "authentication");
  const encryption = requireObject(manifest.encryption, "encryption");
  const kdf = requireObject(encryption.sessionKeyDerivation, "encryption.sessionKeyDerivation");
  const secrets = requireObject(manifest.secrets, "secrets");

  if (connection.enabled !== true) throw new Error("The copied Connection is disabled");
  if (mqttConfig.protocol !== "3.1.1" || mqttConfig.cleanSession !== true) {
    throw new Error("This example requires MQTT 3.1.1 with cleanSession=true");
  }
  if (broker.transport !== "tcp") throw new Error("Unsupported copied MQTT transport");
  if (mqttConfig.clientIdRequirement !== "unique-per-active-session") throw new Error("Unsupported clientIdRequirement");
  if (qos.telemetry !== 1 || qos.commands !== 1 || qos.commandResults !== 1) {
    throw new Error("This example requires copied telemetry/command/result QoS values of 1");
  }
  if (authentication.scheme !== "HMAC-SHA256" || encryption.scheme !== "AES-256-GCM") {
    throw new Error("Unsupported authentication/encryption contract");
  }
  if (kdf.algorithm !== "HKDF-SHA256" || kdf.info !== "SCADA-ENC-v1") {
    throw new Error("Unsupported session-key derivation contract");
  }
  if (secrets.apiKeySecretIncluded !== false) throw new Error("Connection Copy JSON must never contain the API-key secret");

  requireBooleanTag(manifest, INPUT_TAG_ADDRESS, "Input");
  requireBooleanTag(manifest, OUTPUT_TAG_ADDRESS, "Output");

  const clientId = createUniqueClientId();

  return {
    host: requireString(broker, "host"),
    port: Number(broker.port),
    clientId,
    mqttUsername: requireString(mqttConfig, "username"),
    keyId: requireString(identity, "keyId"),
    apiToken: requiredSecret("SCADALGERIA_API_KEY"),
    authChallengeTopic: resolveClientTopic(requireString(topics, "authenticationChallenge"), clientId),
    authResponseTopic: resolveClientTopic(requireString(topics, "authenticationResponse"), clientId),
    telemetryTopic: requireString(topics, "telemetry"),
    commandsTopic: requireString(topics, "commands"),
    commandResultTopic: requireString(topics, "commandResults"),
  };
}

const configuration = loadConnectionConfiguration();


// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
//
// BCM17 is an active-low switch input using a pull-up.
// BCM27 is the digital output controlled by "do.output1".
//
// Verify the actual Raspberry Pi 5 GPIO chip/permissions on the deployment.
// Only connect a safe logic input, current-limited LED, or isolated driver to
// the output pin. Never drive industrial loads directly from the Pi GPIO.
// ============================================================================

const INPUT_GPIO = 17;
const OUTPUT_GPIO = 27;

const digitalInput = new RIO(
  INPUT_GPIO,
  "input",
  { bias: "pull-up" },
);

const digitalOutput = new RIO(
  OUTPUT_GPIO,
  "output",
  { value: 0 },
);

function readDigitalInput(): 0 | 1 {
  const rawValue = digitalInput.read();

  // Active-low switch: 0 V means asserted.
  return rawValue === 0 ? 1 : 0;
}

function writeDigitalOutput(value: 0 | 1): void {
  digitalOutput.write(value);
}


// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
//
// Envelope Seq is replay/order state and must survive process restarts and
// MQTT reconnects. Persist the incremented value before using it.
//
// Command results are cached by CommandDto.Id so normal QoS-1 redelivery does
// not execute the same set-state output twice.
// ============================================================================

const STATE_FILE = ".scadalgeria-state.json";
const MAX_CACHED_RESULTS = 64;

function loadDeviceState() {
  if (!fs.existsSync(STATE_FILE)) {
    return {
      seq: "0",
      results: {},
    };
  }

  return JSON.parse(
    fs.readFileSync(
      STATE_FILE,
      "utf8",
    ),
  );
}

type CommandResult = [string, boolean, string | null, string | null, number];

type DeviceState = {
  seq: string;
  results: Record<string, CommandResult>;
};

let deviceState: DeviceState = loadDeviceState() as DeviceState;

function saveDeviceState(): void {
  const temporaryFile = `${STATE_FILE}.tmp`;

  fs.writeFileSync(
    temporaryFile,
    JSON.stringify(deviceState),
  );

  fs.renameSync(
    temporaryFile,
    STATE_FILE,
  );
}

function reserveNextSequence(): bigint {
  const nextValue = BigInt(deviceState.seq) + 1n;

  deviceState.seq = nextValue.toString();

  saveDeviceState();

  return nextValue;
}

function getCachedCommandResult(commandId: string): CommandResult | null {
  return deviceState.results[commandId] ?? null;
}

function rememberCommandResult(commandId: string, commandResult: CommandResult): void {
  deviceState.results[commandId] = commandResult;

  const ids = Object.keys(deviceState.results);

  while (ids.length > MAX_CACHED_RESULTS) {
    const oldestId = ids.shift();

    if (oldestId) {
      delete deviceState.results[oldestId];
    }
  }

  saveDeviceState();
}


// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
//
// Authentication challenge:
//
//   [ ServerNonce:bin16, ExpiresAtUnixMs:int64 ]
//
// Authentication proof:
//
//   HMAC-SHA256(
//       key     = UTF8(fullApiKeyToken),
//       message = ServerNonce || ClientNonce || UTF8(ClientId)
//   )
//
// Authentication response:
//
//   [ ClientNonce:bin16, Auth:bin32 ]
//
// Session key:
//
//   HKDF-SHA256(
//       IKM    = UTF8(fullApiKeyToken),
//       salt   = ServerNonce || ClientNonce,
//       info   = UTF8("SCADA-ENC-v1"),
//       length = 32
//   )
// ============================================================================

let sessionKey: Buffer | null = null;
let authenticated = false;

function packMessagePack(value: unknown): Buffer {
  return Buffer.from(
    encode(
      value,
      { useBigInt64: true },
    ),
  );
}

function unpackMessagePack(payload: Uint8Array): unknown {
  return decode(
    payload,
    { useBigInt64: true },
  );
}

function currentUnixMilliseconds(): bigint {
  return BigInt(Date.now());
}

function requireNonNegativeInteger(value: unknown, fieldName: string): bigint {
  if (
    typeof value === "bigint"
    && value >= 0n
  ) {
    return value;
  }

  if (
    typeof value === "number"
    && Number.isSafeInteger(value)
    && value >= 0
  ) {
    return BigInt(value);
  }

  throw new Error(`${fieldName} must be a non-negative integer`);
}

function deriveSessionKey(serverNonce: Buffer, clientNonce: Buffer): Buffer {
  return Buffer.from(
    hkdfSync(
      "sha256",
      Buffer.from(configuration.apiToken, "utf8"),
      Buffer.concat([
        serverNonce,
        clientNonce,
      ]),
      Buffer.from("SCADA-ENC-v1", "utf8"),
      32,
    ),
  );
}

function buildAuthenticationProof(serverNonce: Buffer, clientNonce: Buffer): Buffer {
  const proofMessage = Buffer.concat([
    serverNonce,
    clientNonce,
    Buffer.from(configuration.clientId, "utf8"),
  ]);

  return createHmac(
    "sha256",
    Buffer.from(configuration.apiToken, "utf8"),
  )
    .update(proofMessage)
    .digest();
}

function clearAuthenticatedSession(): void {
  sessionKey = null;
  authenticated = false;
}


// ============================================================================
// STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
//
// AesGcmEnvelopeDto:
//
//   [0] KeyId
//   [1] Nonce        12 random bytes
//   [2] Ciphertext
//   [3] GcmTag       16 bytes
//   [4] Seq          durable uint64
//   [5] TsUnixMs     current UTC milliseconds
//
// AAD is exactly:
//
//   UInt64BE(Seq) || UInt64BE(TsUnixMs)
//
// The nonce is cryptographically random for every envelope. Do not confuse it
// with Seq; reconnecting creates a new session key but does NOT reset Seq.
// ============================================================================

function buildEnvelopeAad(sequence: bigint, timestampMs: bigint): Buffer {
  const aad = Buffer.alloc(16);

  aad.writeBigUInt64BE(
    sequence,
    0,
  );

  aad.writeBigUInt64BE(
    timestampMs,
    8,
  );

  return aad;
}

function encryptScadalgeriaPayload(innerMessage: unknown[]): Buffer {
  if (!sessionKey) {
    throw new Error("SCADALGERIA session is not authenticated");
  }

  const sequence = reserveNextSequence();
  const timestampMs = currentUnixMilliseconds();
  const nonce = randomBytes(12);

  const aad = buildEnvelopeAad(
    sequence,
    timestampMs,
  );

  const cipher = createCipheriv(
    "aes-256-gcm",
    sessionKey,
    nonce,
    { authTagLength: 16 },
  );

  cipher.setAAD(aad);

  const ciphertext = Buffer.concat([
    cipher.update(
      packMessagePack(innerMessage),
    ),
    cipher.final(),
  ]);

  const gcmTag = cipher.getAuthTag();

  return packMessagePack([
    configuration.keyId,
    nonce,
    ciphertext,
    gcmTag,
    sequence,
    timestampMs,
  ]);
}

function decryptScadalgeriaPayload(encryptedPayload: Uint8Array): unknown {
  if (!sessionKey) {
    throw new Error("SCADALGERIA session is not authenticated");
  }

  const envelope = unpackMessagePack(
    encryptedPayload,
  );

  if (
    !Array.isArray(envelope)
    || envelope.length !== 6
  ) {
    throw new Error("Malformed SCADALGERIA encrypted envelope");
  }

  const [
    keyId,
    nonceValue,
    ciphertextValue,
    tagValue,
    sequenceValue,
    timestampValue,
  ] = envelope;

  if (keyId !== configuration.keyId) {
    throw new Error("Encrypted envelope KeyId does not match this credential");
  }

  if (!(nonceValue instanceof Uint8Array) || nonceValue.length !== 12) {
    throw new Error("Encrypted envelope nonce must be 12 bytes");
  }

  if (!(ciphertextValue instanceof Uint8Array)) {
    throw new Error("Encrypted envelope ciphertext must be binary");
  }

  if (!(tagValue instanceof Uint8Array) || tagValue.length !== 16) {
    throw new Error("Encrypted envelope GCM tag must be 16 bytes");
  }

  const sequence = requireNonNegativeInteger(
    sequenceValue,
    "Envelope Seq",
  );

  const timestampMs = requireNonNegativeInteger(
    timestampValue,
    "Envelope TsUnixMs",
  );

  const decipher = createDecipheriv(
    "aes-256-gcm",
    sessionKey,
    Buffer.from(nonceValue),
    { authTagLength: 16 },
  );

  decipher.setAAD(
    buildEnvelopeAad(
      sequence,
      timestampMs,
    ),
  );

  decipher.setAuthTag(
    Buffer.from(tagValue),
  );

  const plaintext = Buffer.concat([
    decipher.update(
      Buffer.from(ciphertextValue),
    ),
    decipher.final(),
  ]);

  return unpackMessagePack(
    plaintext,
  );
}

function publishEncryptedMessage(topic: string, innerMessage: unknown[]): void {
  const payload = encryptScadalgeriaPayload(
    innerMessage,
  );

  mqttClient.publish(
    topic,
    payload,
    {
      qos: 1,
      retain: false,
    },
    (error) => {
      if (error) {
        console.error(
          "MQTT publish failed locally:",
          error.message,
        );
      }
    },
  );
}


// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
//
// TagFrameDto:
//
//   [ "di.input1", ValNum, null, 0, 192 ]
//
// Quality 192 means Good.
// Frame TsUnixMs=0 asks the Direct Firmware path to stamp capture time.
// The encrypted envelope timestamp still uses current UTC milliseconds.
//
// TagFrameBatchDto:
//
//   [ [TagFrameDto], null, 1 ]
// ============================================================================

function publishDigitalInputTelemetry(): void {
  const inputValue = readDigitalInput();

  const tagFrame = [
    INPUT_TAG_ADDRESS,
    Number(inputValue),
    null,
    0,
    192,
  ];

  const tagFrameBatch = [
    [tagFrame],
    null,
    1,
  ];

  publishEncryptedMessage(
    configuration.telemetryTopic,
    tagFrameBatch,
  );

  console.log(
    `Telemetry sent: ${INPUT_TAG_ADDRESS}=${inputValue}`,
  );
}


// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
//
// CommandDto:
//
//   [
//     Id,
//     TagAddress,
//     Value,
//     Timestamp,
//     ExpiryEpochSeconds,
//     LeasedUntil,
//     TraceId,
//     RequiresConfirmation,
//     Confirmed,
//     2,
//   ]
//
// CommandResultDto:
//
//   [ CommandId, Success, ErrorMessage, Data, 1 ]
// ============================================================================

function parseOutputBit(value: unknown): 0 | 1 {
  if (value === true || value === 1 || value === 1n) {
    return 1;
  }

  if (value === false || value === 0 || value === 0n) {
    return 0;
  }

  throw new Error("do.output1 accepts only 0 or 1");
}

function executeOutputCommand(command: unknown[]): CommandResult {
  if (command.length !== 10) {
    throw new Error("CommandDto must contain exactly 10 fields");
  }

  const commandId = command[0];
  const tagAddress = command[1];
  const commandValue = command[2];

  const expiryEpochSeconds = requireNonNegativeInteger(
    command[4],
    "Command Expiry",
  );

  const requiresConfirmation = command[7];
  const confirmed = command[8];

  const schemaVersion = requireNonNegativeInteger(
    command[9],
    "Command SchemaVersion",
  );

  if (typeof commandId !== "string" || commandId.length === 0) {
    throw new Error("Command Id must be a non-empty string");
  }

  if (typeof tagAddress !== "string") {
    throw new Error("Command TagAddress must be a string");
  }

  if (
    typeof requiresConfirmation !== "boolean"
    || typeof confirmed !== "boolean"
  ) {
    throw new Error("Command confirmation fields must be booleans");
  }

  if (schemaVersion !== 2n) {
    throw new Error(`Unsupported CommandDto schema version: ${schemaVersion}`);
  }

  if (tagAddress !== OUTPUT_TAG_ADDRESS) {
    throw new Error(`Unsupported command address: ${tagAddress}`);
  }

  const nowEpochSeconds = BigInt(
    Math.floor(Date.now() / 1000),
  );

  if (expiryEpochSeconds <= nowEpochSeconds) {
    throw new Error("Command expired");
  }

  if (requiresConfirmation && !confirmed) {
    throw new Error("Command requires operator confirmation");
  }

  const outputValue = parseOutputBit(
    commandValue,
  );

  writeDigitalOutput(
    outputValue,
  );

  console.log(
    `Command applied: ${OUTPUT_TAG_ADDRESS}=${outputValue}`,
  );

  return [
    commandId,
    true,
    null,
    JSON.stringify({
      appliedValue: outputValue,
    }),
    1,
  ];
}

function handleScadalgeriaCommand(encryptedPayload: Uint8Array): void {
  const commandValue = decryptScadalgeriaPayload(
    encryptedPayload,
  );

  if (!Array.isArray(commandValue)) {
    throw new Error("Decrypted command is not a MessagePack array");
  }

  const command = commandValue;


  if (
    command.length === 0
    || typeof command[0] !== "string"
    || command[0].length === 0
  ) {
    throw new Error("Malformed command does not contain a valid CommandId");
  }

  const commandId = command[0];
  const cachedResult = getCachedCommandResult(commandId);

  if (cachedResult) {
    console.log(
      `Command redelivery detected: ${commandId}; returning cached result`,
    );

    publishEncryptedMessage(
      configuration.commandResultTopic,
      cachedResult,
    );

    return;
  }

  let commandResult: CommandResult;

  try {
    commandResult = executeOutputCommand(
      command,
    );
  } catch (error) {
    const message = error instanceof Error
      ? error.message
      : String(error);

    commandResult = [
      commandId,
      false,
      message.slice(0, 256),
      null,
      1,
    ];

    console.warn(
      `Command rejected: ${message}`,
    );
  }

  rememberCommandResult(
    commandId,
    commandResult,
  );

  publishEncryptedMessage(
    configuration.commandResultTopic,
    commandResult,
  );
}


// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
//
// MQTT.js is explicitly forced to protocolVersion=4 (MQTT 3.1.1).
// `clean: true` matches the SCADALGERIA requirement.
//
// On every reconnect:
//
//   old session key is discarded
//   authenticated=false
//   only authChallenge is subscribed
//   challenge/response runs again
//
// Telemetry is never sent while authentication is incomplete.
// ============================================================================

const mqttClient = mqtt.connect(
  `mqtt://${configuration.host}:${configuration.port}`,
  {
    clientId: configuration.clientId,
    username: configuration.mqttUsername,
    password: "",
    protocolVersion: 4,
    clean: true,

    // Keep reconnects bounded. Production clients should use the strongest
    // exponential-backoff + jitter strategy available in the surrounding app.
    reconnectPeriod: 5000,
  },
);

mqttClient.on(
  "connect",
  () => {
    clearAuthenticatedSession();

    console.log(
      "MQTT connected; waiting for a fresh SCADALGERIA challenge",
    );

    mqttClient.subscribe(
      configuration.authChallengeTopic,
      { qos: 1 },
      (error, grants) => {
        if (
          error
          || !grants
          || grants.length !== 1
          || grants[0].qos !== 1
        ) {
          console.error(
            "Pre-auth challenge subscription was not granted at QoS 1",
          );

          mqttClient.end(true);
        }
      },
    );
  },
);

mqttClient.on(
  "close",
  () => {
    clearAuthenticatedSession();
  },
);

mqttClient.on(
  "message",
  (topic, payload) => {
    try {
      if (topic === configuration.authChallengeTopic) {
        const challenge = unpackMessagePack(payload);

        if (!Array.isArray(challenge) || challenge.length !== 2) {
          throw new Error("Malformed authentication challenge");
        }

        const serverNonceValue = challenge[0];
        const expiresAtValue = challenge[1];

        if (!(serverNonceValue instanceof Uint8Array)) {
          throw new Error("Authentication ServerNonce must be binary");
        }

        const serverNonce = Buffer.from(serverNonceValue);
        const expiresAtUnixMs = requireNonNegativeInteger(
          expiresAtValue,
          "Challenge ExpiresAtUnixMs",
        );

        if (serverNonce.length !== 16) {
          throw new Error("Authentication ServerNonce must be 16 bytes");
        }

        if (currentUnixMilliseconds() >= expiresAtUnixMs) {
          throw new Error("SCADALGERIA authentication challenge expired");
        }

        const clientNonce = randomBytes(16);

        const authenticationProof = buildAuthenticationProof(
          serverNonce,
          clientNonce,
        );

        sessionKey = deriveSessionKey(
          serverNonce,
          clientNonce,
        );

        const authResponse = packMessagePack([
          clientNonce,
          authenticationProof,
        ]);

        mqttClient.publish(
          configuration.authResponseTopic,
          authResponse,
          {
            qos: 1,
            retain: false,
          },
          (publishError) => {
            if (publishError) {
              console.error(
                "Authentication response publish failed:",
                publishError.message,
              );

              mqttClient.end(true);
              return;
            }

            // Successful post-auth command subscription is the concrete
            // promotion proof used by this bidirectional example.
            mqttClient.subscribe(
              configuration.commandsTopic,
              { qos: 1 },
              (subscribeError, grants) => {
                if (
                  subscribeError
                  || !grants
                  || grants.length !== 1
                  || grants[0].qos !== 1
                ) {
                  console.error(
                    "Post-auth command subscription was not granted at QoS 1",
                  );

                  mqttClient.end(true);
                  return;
                }

                authenticated = true;

                console.log(
                  "SCADALGERIA session authenticated; telemetry and commands are enabled",
                );
              },
            );
          },
        );

        return;
      }

      if (
        topic === configuration.commandsTopic
        && authenticated
      ) {
        handleScadalgeriaCommand(
          payload,
        );
      }
    } catch (error) {
      const message = error instanceof Error
        ? error.message
        : String(error);

      // Never log API tokens or the AES session key.
      console.error(
        `SCADALGERIA protocol error: ${message}`,
      );
    }
  },
);

const telemetryTimer = setInterval(
  () => {
    if (!authenticated) {
      return;
    }

    publishDigitalInputTelemetry();
  },
  1000,
);

process.on(
  "SIGINT",
  () => {
    clearInterval(telemetryTimer);

    mqttClient.end(true);

    digitalInput.close();
    digitalOutput.close();

    process.exit(0);
  },
);
