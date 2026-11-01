# SCADALGERIA Direct Firmware Examples

Practical MQTT examples for firmware and external software clients connecting directly to SCADALGERIA.

📘 **Start with the [SCADALGERIA Quick Start](https://github.com/Belalia-Industries/SCADALGERIA-Launch-Site/blob/main/docs/en/quick-start.mdx).**

## 🚀 Provision once, use the same pattern in every language

Every example uses the same public setup:

```text
Connection → Copy firmware configuration → Copy JSON
                         │
                         └── non-secret `scadalgeria-connection.json`

Administration → Access → API Keys
                         │
                         └── API-key secret supplied separately

copied JSON + separate API-key secret
                │
                ▼
MQTT 3.1.1 authentication
                │
                ├── encrypted `di.input1` telemetry
                ├── encrypted `do.output1` command
                └── encrypted command result
```

The copied JSON is authoritative for the MQTT endpoint, username, key ID, authentication topic templates, telemetry/command/result topics, QoS, policies, and tag definitions. The API-key secret is intentionally excluded from that JSON and must be provisioned separately. The separately supplied secret must be for the API key identified by the copied `identity.keyId`.

> 🔒 **Configuration privacy:** The copied JSON intentionally contains no API-key secret, but it can contain environment-specific identifiers, tag names, and connection metadata. Do not publish a real production copy. The JSON shown in this repository uses placeholders only.

## 🧪 Example I/O

All language/device snippets demonstrate the same small control loop:

```text
read local digital input
        ↓
Boolean tag `di.input1`
        ↓
encrypted telemetry / QoS 1
        ↓
SCADALGERIA
        ↓
encrypted command for `do.output1`
        ↓
validate + deduplicate
        ↓
write local digital output
        ↓
encrypted command result / QoS 1
```

## 🗂️ Choose an example

| Language | Target | Example |
|---|---|---|
| C | ESP32 / ESP-IDF | [`C/ESP32-ESP-IDF`](C/ESP32-ESP-IDF/) |
| C | Raspberry Pi 5 / Linux | [`C/External-Applications`](C/External-Applications/) |
| C++ | ESP32 / Arduino | [`CPP/ESP32-Arduino`](CPP/ESP32-Arduino/) |
| C++ | ESP32 / ESP-IDF | [`CPP/ESP32-ESP-IDF`](CPP/ESP32-ESP-IDF/) |
| C++ | Raspberry Pi 5 / Linux | [`CPP/External-Applications`](CPP/External-Applications/) |
| C# | Raspberry Pi 5 / Linux | [`CSharp/External-Applications`](CSharp/External-Applications/) |
| Go | Raspberry Pi 5 / Linux | [`Go/External-Applications`](Go/External-Applications/) |
| Java | Raspberry Pi 5 / Linux | [`Java/External-Applications`](Java/External-Applications/) |
| JavaScript | Raspberry Pi 5 / Node.js | [`JavaScript/External-Applications`](JavaScript/External-Applications/) |
| MicroPython | ESP32 | [`MicroPython/ESP32`](MicroPython/ESP32/) |
| Python | Raspberry Pi 5 / Linux | [`Python/External-Applications`](Python/External-Applications/) |
| Rust | Raspberry Pi 5 / Linux | [`Rust/External-Applications`](Rust/External-Applications/) |
| TypeScript | Raspberry Pi 5 / Node.js | [`TypeScript/External-Applications`](TypeScript/External-Applications/) |

> ℹ️ `External-Applications` means a software client implementing the same Direct Firmware MQTT protocol. It can publish telemetry, receive commands, and publish command results just like embedded firmware.

## 🧩 One familiar source layout

Every source uses the same nine stages: imports, **Connection Copy JSON + API-key secret**, local I/O, durable state, authentication/session crypto, MessagePack/AES-GCM, telemetry, command execution/result, and MQTT lifecycle/reconnect behavior.

The snippets favor readable methods and comments over minimum line count. Package/runtime versions, package API signatures, GPIO wiring, protocol byte layouts, rejection behavior, replay handling, and production warnings are documented in each companion README.

## 🔐 Core rules demonstrated by every example

- Use the copied JSON as configuration authority; do not hand-build topic paths or the canonical MQTT username.
- Generate a unique ClientId for the running client instance and substitute only the copied `{clientId}` authentication-topic placeholder.
- Keep the full API-key secret separate from the copied JSON and MQTT password.
- Use MQTT 3.1.1, `CleanSession=true`, and the copied QoS values.
- Complete challenge/response before subscribing to commands or publishing application payloads.
- Derive the per-session key with HKDF-SHA256 and encrypt telemetry/results with AES-256-GCM.
- Persist the device→platform `Seq` across reconnects and restarts.
- Deduplicate command IDs before physical actuation and return the cached final result on ordinary redelivery.
- Treat the copied `telemetryPolicy` and tag contract as authoritative.

## ⚠️ Hardware safety

The GPIO examples use a low-voltage switch/button and a current-limited LED or logic-level interface. Never connect industrial field voltage, relay coils, motors, contactors, or inductive loads directly to an ESP32 or Raspberry Pi GPIO. Use correctly rated isolation and driver hardware.

These are intentionally single-file integration snippets rather than complete build projects. The surrounding application or firmware still owns network enrollment, secret injection, service supervision, watchdogs, OTA/update strategy, and production diagnostics.
