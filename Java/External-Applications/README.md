# Java · Raspberry Pi 5 Direct Firmware

🎯 **Target:** Raspberry Pi 5 · Linux · Java 27.0.1  
📄 **Companion source:** [`Main.java`](Main.java)

📘 **Start here:** [SCADALGERIA Quick Start](https://github.com/Belalia-Industries/SCADALGERIA-Launch-Site/blob/main/docs/en/quick-start.mdx)

> ℹ️ **Repository naming note:** `External-Applications` examples are software clients using the SCADALGERIA Direct Firmware MQTT protocol. The client authenticates, publishes telemetry, receives commands, and publishes command results over MQTT 3.1.1.

## 🚦 What the snippet demonstrates

```text
local digital input di.input1
        ↓
encrypted MQTT telemetry
        ↓
SCADALGERIA platform
        ↓
encrypted do.output1 command
        ↓
validate + deduplicate + write local digital output
        ↓
encrypted command result
```

The file is intentionally a protocol/I-O snippet rather than a complete build project. Build manifests, Wi-Fi provisioning UI, service management, OTA, watchdog policy, and production secret provisioning belong in the surrounding application.

## 🧩 Source walkthrough

Every source file deliberately follows the same nine-stage layout so you can move between languages without relearning the integration structure:

1. **Imports** — runtime, MQTT, MessagePack, cryptography, and GPIO dependencies.
2. **Connection Copy JSON + API-key secret** — parse the non-secret copied configuration, validate it, generate the active-session ClientId, and load the secret separately.
3. **Local digital I/O** — read `di.input1` and write `do.output1`.
4. **Durable device state** — replay `Seq` and command-result deduplication state.
5. **Authentication cryptography + session state** — challenge proof, HKDF session key, and reconnect invalidation.
6. **MessagePack DTOs + AES-GCM envelope** — byte-for-byte SCADALGERIA wire helpers.
7. **MQTT helpers + authentication + telemetry** — challenge promotion and encrypted input publication.
8. **Command validation + local actuation + result** — decrypt, validate, deduplicate, actuate, and publish the cached result.
9. **MQTT lifecycle + reconnect** — MQTT 3.1.1 setup, reconnect behavior, re-authentication, and main loop.

The examples are intentionally **readable rather than code-golfed**. Small helpers and explanatory comments are retained where they make a protocol invariant, safety rule, or recovery rule easier to audit.

## 🧭 SCADALGERIA Direct Firmware wire contract

| Item | Required value |
|---|---|
| Broker | `mqtt.broker.host` from the copied JSON |
| Port / transport | `mqtt.broker.port` + `mqtt.broker.transport` from the copied JSON |
| MQTT | **3.1.1** only |
| Session | `CleanSession=true` |
| QoS | `1` for auth, telemetry, commands, results |
| MQTT password | Empty — **never put the API-key token here** |
| Authentication | HMAC-SHA256 challenge/response |
| Session key | HKDF-SHA256, info `SCADA-ENC-v1`, 32 bytes |
| Payload encryption | AES-256-GCM, random 12-byte nonce, 16-byte tag |
| AAD | `UInt64BE(Seq) || UInt64BE(TsUnixMs)` |
| Serialization | MessagePack positional arrays matching numeric `[Key(n)]` DTOs |

The Direct Firmware MQTT endpoint is plain TCP. AES-GCM protects the application payload, **not** MQTT metadata. For production deployments, restrict TCP 1883 to approved client networks or place the MQTT path inside an approved private tunnel/VPN. Do not assume `8883`/MQTTS is currently available.

### Public provisioning workflow: Copy JSON + separate API key

Start with the **[SCADALGERIA Quick Start](https://github.com/Belalia-Industries/SCADALGERIA-Launch-Site/blob/main/docs/en/quick-start.mdx)**, then provision this example as follows:

1. Create the Direct Firmware Connection and define the two tags used by this example: `di.input1` as a Boolean **Input** and `do.output1` as a Boolean **Output**.
2. Create one source-bound API key for that Connection. The full bidirectional example needs these scopes:

```json
{
  "scopes": [
    "connections:read",
    "ingest:write",
    "commands:read",
    "commands:ack"
  ]
}
```

3. In the Connection actions, choose **Copy firmware configuration → Copy JSON**.
4. Save that non-secret JSON unchanged as `scadalgeria-connection.json` (or the target-specific path documented below).
5. Supply the **full API-key secret separately**. Never add it to the copied JSON, source control, logs, MQTT password, or screenshots. The secret must belong to the API key identified by the copied `identity.keyId`; a secret from another key will not authenticate this manifest.

The copied document is the configuration authority. The examples read these fields directly rather than asking you to manually copy broker/topic/identity constants into source code:

> 🔒 **Configuration privacy:** The copied JSON intentionally contains no API-key secret, but it can contain environment-specific identifiers, tag names, and connection metadata. Do not publish a real production copy. The JSON shown in this repository uses placeholders only.

```json
{
  "schema": "scadalgeria.direct-firmware.connection",
  "schemaVersion": 1,
  "connection": {
    "sourceId": "...",
    "enabled": true
  },
  "identity": {
    "keyId": "..."
  },
  "mqtt": {
    "protocol": "3.1.1",
    "cleanSession": true,
    "broker": {
      "host": "...",
      "port": 1883,
      "transport": "tcp"
    },
    "clientIdRequirement": "unique-per-active-session",
    "username": "...",
    "topics": {
      "authenticationChallenge": ".../{clientId}/auth/challenge",
      "authenticationResponse": ".../{clientId}/auth/response",
      "telemetry": ".../tags",
      "commands": ".../commands",
      "commandResults": ".../commands/result"
    },
    "qos": {
      "telemetry": 1,
      "commands": 1,
      "commandResults": 1
    }
  },
  "authentication": { "scheme": "HMAC-SHA256" },
  "encryption": {
    "scheme": "AES-256-GCM",
    "sessionKeyDerivation": {
      "algorithm": "HKDF-SHA256",
      "info": "SCADA-ENC-v1"
    }
  },
  "tags": [
    { "address": "di.input1", "dataType": "Boolean", "direction": "Input" },
    { "address": "do.output1", "dataType": "Boolean", "direction": "Output" }
  ],
  "secrets": {
    "apiKeySecretIncluded": false
  }
}
```

> 🔐 **Configuration is not the credential.** The copied JSON contains the key **ID**, username, topics, protocol/policy metadata, and tags, but not the API-key **secret**. The secret is the HMAC/HKDF root key and remains a separate provisioning input.

### Client ID and authentication topics

The copied configuration intentionally contains authentication topic **templates** with `{clientId}` and declares `clientIdRequirement: "unique-per-active-session"`.

Each example therefore:

```text
1. generates one cryptographically random ClientId for the running client instance;
2. replaces exactly one {clientId} placeholder in authenticationChallenge;
3. replaces exactly one {clientId} placeholder in authenticationResponse;
4. uses telemetry, commands, and commandResults exactly as copied;
5. never reconstructs tenant/project/source topic paths itself.
```

A reconnect by the same running client may reuse its generated ClientId; two simultaneously active clients must not share a ClientId.

### Configuration inputs used by this host example

| Input | Purpose | Secret? |
|---|---|---:|
| `scadalgeria-connection.json` | Exact Connection Copy JSON | No |
| `SCADALGERIA_CONFIG_FILE` | Optional path override for the JSON file | No |
| `SCADALGERIA_API_KEY` | Full source-bound API-key secret | **Yes** |

The code deliberately has no environment variables for broker host, key ID, MQTT username, ClientId, or topics; those values come from the copied JSON.

## 🔐 Authentication and encryption, byte-for-byte

Challenge payload:

```text
[ ServerNonce:bin16, ExpiresAtUnixMs:int64 ]
```

Proof:

```text
ClientNonce = CSPRNG(16)
Auth = HMAC-SHA256(
    key     = UTF8(fullApiKeyToken),
    message = ServerNonce || ClientNonce || UTF8(ClientId)
)
```

Response payload:

```text
[ ClientNonce:bin16, Auth:bin32 ]
```

Session key:

```text
HKDF-SHA256(
    IKM    = UTF8(fullApiKeyToken),
    salt   = ServerNonce || ClientNonce,
    info   = UTF8("SCADA-ENC-v1"),
    length = 32
)
```

Encrypted envelope:

```text
[ KeyId, Nonce:bin12, Ciphertext:bin, GcmTag:bin16, Seq:uint64, TsUnixMs:uint64 ]
```

Use a **fresh cryptographically random 12-byte GCM nonce** for every envelope. Never reuse a `(session key, nonce)` pair. `Seq` is a different control: it is the monotonically increasing device→platform replay sequence and must survive reconnects/reboots/power loss.

## 📡 Payloads used by this example

Digital input telemetry is sent as numeric `0.0` / `1.0` with Good quality:

```text
TagFrameBatchDto = [ Frames, TraceId|null, 1 ]
TagFrameDto      = [ "di.input1", ValNum, null, 0, 192 ]
```

`TsUnixMs=0` inside the tag frame asks the platform to stamp capture time for Direct Firmware. The **outer envelope timestamp must still be current UTC milliseconds**.

The output command is expected on `do.output1`:

```text
CommandDto = [
  Id, TagAddress, Value, Timestamp, ExpiryEpochSeconds,
  LeasedUntil|null, TraceId|null,
  RequiresConfirmation, Confirmed, 2
]
```

The snippet rejects expired/unconfirmed/unsupported commands, writes only `0` or `1`, and sends:

```text
CommandResultDto = [ CommandId, Success, ErrorMessage|null, Data|null, 1 ]
```

The same command `Id` can be delivered more than once. This example caches a final result so ordinary redelivery is answered without repeating the handler. The demonstrated output is an **idempotent set-state operation** (`0`/`1`). For a non-idempotent physical action, a result cache alone cannot guarantee exactly-once behavior across a power loss between actuation and persistence; use a durable command journal/state machine and reconcile an incomplete operation before accepting redelivery.

## ⚠️ Warnings: Platform rejection / abuse rules to design around

| Bad client behavior | Expected consequence |
|---|---|
| MQTT 5, `CleanSession=false`, malformed canonical identity | CONNECT rejection |
| Subscribing to command/wildcard topics before auth | subscription rejection / disconnect |
| Invalid, expired, revoked, wrong-source key | authorization failure |
| Wrong HMAC proof / malformed auth response / expired challenge | auth failure / disconnect |
| Wrong tenant/project/source topic | source-identity ACL violation |
| Wrong envelope `KeyId`, bad GCM tag, malformed envelope | crypto rejection; repeated abuse can disconnect |
| Reset/replayed `Seq` or stale outer timestamp | replay/stale drop |
| Unknown tag, duplicate address, invalid quality/type/range, reserved `$sys.*` | atomic telemetry batch rejection |
| Sustained rate/burst excess | rate-limit drops, then abuse disconnect/cooldown |
| Tight reconnect loop | avoid; use exponential backoff + jitter |

A local MQTT `publish()`/PUBACK only proves MQTT transport progress. It does **not** prove the platform accepted the telemetry semantically. Use platform readback/observability when validating an integration.


## 📦 Runtime and package versions

| Component | Version | Official documentation |
|---|---:|---|
| Java | **JDK 27.0.1** | [Oracle Java downloads](https://www.oracle.com/java/technologies/downloads/) · [JDK 27.0.1 release notes](https://www.oracle.com/java/technologies/javase/27-0-1-relnotes.html) |
| Pi4J | **4.0.2** | [Pi4J](https://www.pi4j.com/) · [release notes](https://www.pi4j.com/about/release-notes/) |
| Eclipse Paho Java MQTT v3 | **1.2.5** | [Maven Central](https://central.sonatype.com/artifact/org.eclipse.paho/org.eclipse.paho.client.mqttv3/1.2.5) |
| msgpack-core | **0.9.12** | [Maven Central](https://central.sonatype.com/artifact/org.msgpack/msgpack-core/0.9.12) |
| Jackson Databind | **2.22.4** | [Maven Central](https://central.sonatype.com/artifact/com.fasterxml.jackson.core/jackson-databind/2.22.4) |
| JCA/JCE crypto | bundled | [Java security APIs](https://docs.oracle.com/en/java/javase/27/security/) |

Use your normal Maven/Gradle build and pin these coordinates:

```xml
<dependency><groupId>org.eclipse.paho</groupId><artifactId>org.eclipse.paho.client.mqttv3</artifactId><version>1.2.5</version></dependency>
<dependency><groupId>org.msgpack</groupId><artifactId>msgpack-core</artifactId><version>0.9.12</version></dependency>
<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.22.4</version></dependency>
<!-- Pi4J core + the Raspberry Pi FFM provider from the Pi4J 4.0.2 distribution/build guide. -->
```

Pi4J 4.0.2 requires Java 25 or newer. This example targets the current stable Java SE release, **JDK 27.0.1**; Java 25 remains the current LTS line if your deployment policy prefers LTS.

## 🧩 Package APIs used by the snippet

The following signatures are the concrete API shapes used by this example (or the small adapter contract the snippet defines when a package does not provide a SCADALGERIA-specific helper).

```java
new ObjectMapper().readTree(String json) -> JsonNode
JsonNode.get(name) / path(name) / asText() / asInt() / asBoolean()
new MqttClient("tcp://host:1883", clientId)
MqttConnectOptions.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1_1)
MqttConnectOptions.setCleanSession(true)
MqttConnectOptions.setUserName(username)
MqttConnectOptions.setPassword(new char[0])
MqttClient.connect(options)
MqttClient.subscribeWithResponse(topic, 1, IMqttMessageListener) -> IMqttToken
IMqttToken.getGrantedQos() -> int[]
MqttClient.publish(topic, payload, 1, false)

MessagePack.newDefaultBufferPacker() -> MessageBufferPacker
MessageBufferPacker.packArrayHeader(int)
MessagePack.newDefaultUnpacker(byte[]) -> MessageUnpacker
MessageUnpacker.unpackArrayHeader() -> int

Mac.getInstance("HmacSHA256")
Cipher.getInstance("AES/GCM/NoPadding")
new GCMParameterSpec(128, nonce12)

Pi4J.newAutoContext() -> Context
Context.create(DigitalInputConfig) -> DigitalInput
Context.create(DigitalOutputConfig) -> DigitalOutput
DigitalInput.state() -> DigitalState
DigitalOutput.state(DigitalState)
```

## 🔌 Digital I/O target

Raspberry Pi 5 / Raspberry Pi OS 64-bit. The snippet uses BCM GPIO **17** as an active-low switch input (`PULL_UP`, switch to GND) and BCM GPIO **27** as the output. `di.input1=1` means the switch is asserted/closed. Connect only a current-limited LED or correctly isolated logic input to the output GPIO.



## ✅ Recommended device flow

```text
1. Load Connection Copy JSON + separately protected API key
2. Restore durable outgoing Seq and command-result cache
3. Connect MQTT 3.1.1 with CleanSession=true
4. Subscribe ONLY to authChallenge at QoS 1
5. Validate challenge expiry
6. Create ClientNonce + HMAC proof; derive session key
7. Publish authResponse at QoS 1
8. Subscribe to exact commands topic at QoS 1
9. Read di.input1 and publish encrypted telemetry
10. On command: validate schema/address/expiry/confirmation
11. Return cached result if command ID was already executed
12. Otherwise write do.output1 once, durably remember result, publish result
13. On reconnect: discard session key, repeat auth; DO NOT reset Seq
```


## 🛡️ Production remarks

- Store the root API token in the strongest secret storage available on the target; never log it, put it in MQTT topics, telemetry, URLs, crash dumps, or the MQTT password.
- Persist `Seq` **before** using it for a new logical device→platform message. Skipping a number after a crash is safe; reusing a number is not.
- On **every MQTT reconnect**, clear the authenticated flag and old session key, repeat challenge authentication, and derive a new session key; never reuse ciphertext or a previous session key across sessions.
- Port `1883` is plain TCP in the Direct Firmware endpoint. Payloads are application-encrypted, but MQTT metadata is visible; production deployments should restrict device egress/source IPs or use an approved private tunnel or use an approved private tunnel/VPN when transport-level protection is required.
- Keep UTC synchronized. Authentication challenge expiry and the encrypted envelope replay window are time-sensitive.
- Enforce `telemetryPolicy` from the copied connection configuration: batch size, rate, burst, payload size, and clock-skew limits must be treated as authoritative.
- Bound offline telemetry queues. Do not reconnect and dump an unlimited backlog at the broker.
- Use exact topics from the copied connection configuration; do not subscribe to `#` or cross-source topics.
- Back off reconnect/auth failures exponentially with jitter. Repeated invalid proofs, crypto failures, ACL violations, and rate abuse are observable security signals.
- If an API key has an IP allowlist, NAT/VPN/cellular egress changes can correctly cause authorization failure.


