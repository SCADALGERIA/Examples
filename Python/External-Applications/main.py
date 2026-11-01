"""
SCADALGERIA Direct Firmware example — Raspberry Pi 5 / Python

This single file demonstrates the complete device-side MQTT lifecycle:

    1. Load the Connection Copy JSON and the separately supplied API key.
    2. Open MQTT 3.1.1 with CleanSession=true.
    3. Complete the SCADALGERIA HMAC challenge/response.
    4. Derive the per-session AES-256-GCM key.
    5. Read one digital input and publish encrypted telemetry.
    6. Receive and decrypt one digital-output command.
    7. Apply the output only after validation and deduplication.
    8. Publish the encrypted command result.
    9. Repeat authentication after every MQTT reconnect.

Hardware used by the snippet:

    BCM17 -> active-low digital input -> SCADALGERIA tag "di.input1"
    BCM27 -> digital output          <- SCADALGERIA tag "do.output1"

This is intentionally a protocol + GPIO example, not a complete deployment.
The surrounding application still owns OS service management, watchdogs,
network provisioning, OTA, secret provisioning, and production diagnostics.
"""


# ============================================================================
# STEP 1 OF 9 — IMPORTS AND TARGET NOTES
#
# The example uses normal ecosystem packages rather than a fictional
# SCADALGERIA SDK:
#
#   paho-mqtt     -> MQTT 3.1.1 transport
#   msgpack       -> SCADALGERIA MessagePack DTO arrays
#   cryptography  -> HMAC/HKDF/AES-GCM support
#   gpiod         -> Raspberry Pi 5 GPIO character-device access
#
# The companion README pins the package versions used by this example.
# ============================================================================

import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from pathlib import Path

import gpiod
import msgpack
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from gpiod.line import Bias, Direction, Value


# ============================================================================
# STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
#
# Public provisioning model used by every example in this repository:
#
#   1. In the Connection menu, choose "Copy firmware configuration" →
#      "Copy JSON" and save the non-secret document as
#      `scadalgeria-connection.json`.
#   2. Supply the source-bound API-key secret separately. For this host example
#      it comes from the SCADALGERIA_API_KEY environment variable.
#
# The copied JSON is authoritative for broker, username, key ID, topic
# templates, exact telemetry/command topics, QoS, policies, and tag metadata.
# The API key secret is deliberately NOT present in that JSON.
# ============================================================================

CONNECTION_CONFIG_FILE = Path(
    os.getenv(
        "SCADALGERIA_CONFIG_FILE",
        "scadalgeria-connection.json",
    )
)

INPUT_TAG_ADDRESS = "di.input1"
OUTPUT_TAG_ADDRESS = "do.output1"


def required_secret(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required secret: {name}")
    return value


def require_mapping(value, field_name: str) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError(f"Copied configuration field '{field_name}' must be an object")
    return value


def require_string(mapping: dict, field_name: str) -> str:
    value = mapping.get(field_name)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"Copied configuration field '{field_name}' is missing or invalid")
    return value


def require_boolean_tag(manifest: dict, address: str, direction: str) -> None:
    matches = [
        tag for tag in manifest.get("tags", [])
        if isinstance(tag, dict) and tag.get("address") == address
    ]
    if len(matches) != 1:
        raise RuntimeError(f"Copied configuration must contain exactly one tag '{address}'")
    tag = matches[0]
    if tag.get("dataType") != "Boolean" or tag.get("direction") != direction:
        raise RuntimeError(
            f"Tag '{address}' must be Boolean/{direction} for this digital I/O example"
        )


def resolve_client_topic(template: str, client_id: str) -> str:
    if template.count("{clientId}") != 1:
        raise RuntimeError("Authentication topic template must contain exactly one {clientId}")
    return template.replace("{clientId}", client_id)


def create_unique_client_id() -> str:
    # One generated ID per running client instance. It may be reused by that
    # instance during reconnects, but must not be shared by concurrent clients.
    return "scada-" + secrets.token_hex(8)


def load_connection_configuration() -> dict:
    manifest = json.loads(CONNECTION_CONFIG_FILE.read_text(encoding="utf-8"))

    if manifest.get("schema") != "scadalgeria.direct-firmware.connection":
        raise RuntimeError("Unsupported SCADALGERIA connection configuration schema")
    if manifest.get("schemaVersion") != 1:
        raise RuntimeError("This example supports connection configuration schemaVersion 1")

    connection = require_mapping(manifest.get("connection"), "connection")
    identity = require_mapping(manifest.get("identity"), "identity")
    mqtt_config = require_mapping(manifest.get("mqtt"), "mqtt")
    broker = require_mapping(mqtt_config.get("broker"), "mqtt.broker")
    topics = require_mapping(mqtt_config.get("topics"), "mqtt.topics")
    qos = require_mapping(mqtt_config.get("qos"), "mqtt.qos")
    authentication = require_mapping(manifest.get("authentication"), "authentication")
    encryption = require_mapping(manifest.get("encryption"), "encryption")
    session_kdf = require_mapping(
        encryption.get("sessionKeyDerivation"),
        "encryption.sessionKeyDerivation",
    )
    secrets_contract = require_mapping(manifest.get("secrets"), "secrets")

    if connection.get("enabled") is not True:
        raise RuntimeError("The copied Connection is disabled")
    if mqtt_config.get("protocol") != "3.1.1" or mqtt_config.get("cleanSession") is not True:
        raise RuntimeError("This example requires MQTT 3.1.1 with cleanSession=true")
    if broker.get("transport") != "tcp":
        raise RuntimeError("This example supports the copied TCP MQTT transport")
    if mqtt_config.get("clientIdRequirement") != "unique-per-active-session":
        raise RuntimeError("Unsupported clientIdRequirement in copied configuration")
    if any(qos.get(name) != 1 for name in ("telemetry", "commands", "commandResults")):
        raise RuntimeError("This example requires copied telemetry/command/result QoS values of 1")
    if authentication.get("scheme") != "HMAC-SHA256":
        raise RuntimeError("Unsupported authentication scheme")
    if encryption.get("scheme") != "AES-256-GCM":
        raise RuntimeError("Unsupported encryption scheme")
    if session_kdf.get("algorithm") != "HKDF-SHA256" or session_kdf.get("info") != "SCADA-ENC-v1":
        raise RuntimeError("Unsupported session-key derivation contract")
    if secrets_contract.get("apiKeySecretIncluded") is not False:
        raise RuntimeError("Connection Copy JSON must never contain the API-key secret")

    require_boolean_tag(manifest, INPUT_TAG_ADDRESS, "Input")
    require_boolean_tag(manifest, OUTPUT_TAG_ADDRESS, "Output")

    client_id = create_unique_client_id()

    return {
        "host": require_string(broker, "host"),
        "port": int(broker.get("port")),
        "client_id": client_id,
        "mqtt_username": require_string(mqtt_config, "username"),
        "key_id": require_string(identity, "keyId"),
        "auth_challenge_topic": resolve_client_topic(
            require_string(topics, "authenticationChallenge"), client_id
        ),
        "auth_response_topic": resolve_client_topic(
            require_string(topics, "authenticationResponse"), client_id
        ),
        "telemetry_topic": require_string(topics, "telemetry"),
        "commands_topic": require_string(topics, "commands"),
        "command_result_topic": require_string(topics, "commandResults"),
    }


configuration = load_connection_configuration()

MQTT_HOST = configuration["host"]
MQTT_PORT = configuration["port"]
CLIENT_ID = configuration["client_id"]
MQTT_USERNAME = configuration["mqtt_username"]
API_KEY_ID = configuration["key_id"]
API_KEY_TOKEN = required_secret("SCADALGERIA_API_KEY")
AUTH_CHALLENGE_TOPIC = configuration["auth_challenge_topic"]
AUTH_RESPONSE_TOPIC = configuration["auth_response_topic"]
TELEMETRY_TOPIC = configuration["telemetry_topic"]
COMMAND_TOPIC = configuration["commands_topic"]
COMMAND_RESULT_TOPIC = configuration["command_result_topic"]


# ============================================================================
#
# STEP 3 OF 9 — LOCAL DIGITAL I/O
#
# Raspberry Pi 5 uses the Linux GPIO character-device interface.
# Verify the correct gpiochip with `gpioinfo` on the target image.
#
# This example uses:
#
#   BCM17 -> input with internal pull-up
#            switch asserted when connected to GND
#
#   BCM27 -> output
#            drive only a safe logic input or properly current-limited LED
#
# The local helper methods deliberately return/write 0 or 1 because that is
# also the command value accepted by this example's "do.output1" contract.
# ============================================================================

GPIO_CHIP = os.getenv(
    "SCADALGERIA_GPIO_CHIP",
    "/dev/gpiochip0",
)

INPUT_GPIO = 17
OUTPUT_GPIO = 27


gpio_request = gpiod.request_lines(
    GPIO_CHIP,
    consumer="scadalgeria-example",
    config={
        INPUT_GPIO: gpiod.LineSettings(
            direction=Direction.INPUT,
            bias=Bias.PULL_UP,
        ),
        OUTPUT_GPIO: gpiod.LineSettings(
            direction=Direction.OUTPUT,
            output_value=Value.INACTIVE,
        ),
    },
)


def read_digital_input() -> int:
    """Return 1 when the active-low switch is asserted, otherwise 0."""

    line_value = gpio_request.get_value(INPUT_GPIO)

    return 1 if line_value == Value.INACTIVE else 0


def write_digital_output(value: int) -> None:
    """Apply one validated set-state command to BCM27."""

    gpio_value = (
        Value.ACTIVE
        if value == 1
        else Value.INACTIVE
    )

    gpio_request.set_value(
        OUTPUT_GPIO,
        gpio_value,
    )


# ============================================================================
# STEP 4 OF 9 — DURABLE DEVICE STATE
#
# SCADALGERIA uses the outgoing envelope Seq as replay/order state.
# It must NOT reset when MQTT reconnects or when this process restarts.
#
# The example persists the incremented value BEFORE using it. A crash may
# therefore skip a sequence number, which is safe. Reusing a number is not.
#
# Command results are also cached by CommandDto.Id. MQTT QoS 1 and the command
# pipeline are at-least-once, so the same command can be delivered again.
# A cached final result lets the client answer normal redelivery without
# applying the same set-state output twice.
# ============================================================================

STATE_FILE = Path(".scadalgeria-state.json")
MAX_CACHED_COMMAND_RESULTS = 64


def load_device_state() -> dict:
    try:
        return json.loads(
            STATE_FILE.read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        return {
            "seq": 0,
            "results": {},
        }


device_state = load_device_state()


def save_device_state() -> None:
    temporary_file = STATE_FILE.with_suffix(".tmp")

    temporary_file.write_text(
        json.dumps(
            device_state,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    os.replace(
        temporary_file,
        STATE_FILE,
    )


def reserve_next_sequence() -> int:
    device_state["seq"] += 1

    save_device_state()

    return device_state["seq"]


def get_cached_command_result(command_id: str):
    return device_state["results"].get(command_id)


def remember_command_result(
    command_id: str,
    result: list,
) -> None:
    results = device_state["results"]

    results[command_id] = result

    # This bounded cache is suitable for a public example. A production
    # device can use a durable journal appropriate for its command semantics.
    while len(results) > MAX_CACHED_COMMAND_RESULTS:
        oldest_command_id = next(iter(results))
        results.pop(oldest_command_id)

    save_device_state()


# ============================================================================
# STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
#
# CONNECT success is not yet device authentication.
#
# The authentication flow is:
#
#   MQTT CONNECT
#       ↓
#   subscribe ONLY to authChallenge
#       ↓
#   receive [ServerNonce, ExpiresAtUnixMs]
#       ↓
#   create ClientNonce
#       ↓
#   HMAC-SHA256(ServerNonce || ClientNonce || UTF8(ClientId))
#       ↓
#   publish [ClientNonce, Auth]
#       ↓
#   derive AES session key using HKDF-SHA256
#       ↓
#   subscribe to the exact commands topic
#       ↓
#   successful post-auth SUBACK proves promotion
#
# Every MQTT reconnect repeats this flow and derives a NEW session key.
# ============================================================================

session_key: bytes | None = None
session_key_lock = threading.RLock()

authenticated = threading.Event()
challenge_subscription_message_id: int | None = None
command_subscription_message_id: int | None = None


def set_session_key(value: bytes) -> None:
    global session_key

    with session_key_lock:
        session_key = bytes(value)


def clear_authenticated_session() -> None:
    global session_key

    with session_key_lock:
        session_key = None

    authenticated.clear()


def require_session_key() -> bytes:
    with session_key_lock:
        if session_key is None:
            raise RuntimeError(
                "SCADALGERIA MQTT session is not authenticated"
            )

        return bytes(session_key)


def current_unix_milliseconds() -> int:
    return time.time_ns() // 1_000_000


def pack_messagepack(value) -> bytes:
    return msgpack.packb(
        value,
        use_bin_type=True,
    )


def unpack_messagepack(payload: bytes):
    return msgpack.unpackb(
        payload,
        raw=False,
        timestamp=3,
    )


def require_non_negative_integer(value) -> int:
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    ):
        return value

    raise ValueError(
        "Expected a non-negative integer"
    )


def derive_session_key(
    server_nonce: bytes,
    client_nonce: bytes,
) -> bytes:
    """Implement the current SCADA-ENC-v1 HKDF contract."""

    token_bytes = API_KEY_TOKEN.encode("utf-8")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=server_nonce + client_nonce,
        info=b"SCADA-ENC-v1",
    ).derive(token_bytes)


def build_authentication_proof(
    server_nonce: bytes,
    client_nonce: bytes,
) -> bytes:
    """Build the HMAC proof expected by platform."""

    proof_message = (
        server_nonce
        + client_nonce
        + CLIENT_ID.encode("utf-8")
    )

    return hmac.new(
        API_KEY_TOKEN.encode("utf-8"),
        proof_message,
        hashlib.sha256,
    ).digest()


def authenticate_with_scadalgeria(
    client: mqtt.Client,
    challenge_payload: bytes,
) -> None:
    global command_subscription_message_id

    challenge = unpack_messagepack(
        challenge_payload
    )

    # MqttAuthChallengeDto:
    #
    #   [0] ServerNonce       byte[16]
    #   [1] ExpiresAtUnixMs   int64
    if (
        not isinstance(challenge, list)
        or len(challenge) != 2
    ):
        raise ValueError(
            "Malformed SCADALGERIA authentication challenge"
        )

    server_nonce = challenge[0]
    expires_at_unix_ms = require_non_negative_integer(
        challenge[1]
    )

    if (
        not isinstance(server_nonce, bytes)
        or len(server_nonce) != 16
    ):
        raise ValueError(
            "Authentication ServerNonce must be 16 bytes"
        )

    if current_unix_milliseconds() >= expires_at_unix_ms:
        raise ValueError(
            "SCADALGERIA authentication challenge expired"
        )

    client_nonce = os.urandom(16)

    authentication_proof = build_authentication_proof(
        server_nonce,
        client_nonce,
    )

    new_session_key = derive_session_key(
        server_nonce,
        client_nonce,
    )

    # MqttAuthResponseDto:
    #
    #   [0] ClientNonce   byte[16]
    #   [1] Auth          byte[32]
    auth_response = pack_messagepack(
        [
            client_nonce,
            authentication_proof,
        ]
    )

    set_session_key(
        new_session_key
    )

    publish_info = client.publish(
        AUTH_RESPONSE_TOPIC,
        auth_response,
        qos=1,
        retain=False,
    )

    if publish_info.rc != mqtt.MQTT_ERR_SUCCESS:
        clear_authenticated_session()

        raise RuntimeError(
            f"Authentication response publish failed locally: {publish_info.rc}"
        )

    # There is no separate custom AUTH_OK packet. Asking platform for the exact
    # post-auth command subscription provides a concrete promotion check.
    subscribe_result, command_subscription_message_id = client.subscribe(
        COMMAND_TOPIC,
        qos=1,
    )

    if subscribe_result != mqtt.MQTT_ERR_SUCCESS:
        clear_authenticated_session()

        raise RuntimeError(
            "Command subscription request failed locally"
        )


# ============================================================================
# STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
#
# Telemetry, commands, and command results use the same envelope shape:
#
#   AesGcmEnvelopeDto = [
#       KeyId,
#       Nonce,          # 12 random bytes
#       Ciphertext,
#       GcmTag,         # 16 bytes
#       Seq,
#       TsUnixMs,
#   ]
#
# AES-GCM AAD is exactly:
#
#   UInt64BE(Seq) || UInt64BE(TsUnixMs)
#
# Nonce and Seq solve different problems:
#
#   Nonce -> cryptographic uniqueness for AES-GCM in this session
#   Seq   -> durable device→platform replay/order identity
#
# Never reuse a (session key, nonce) pair. The SCADALGERIA Direct Firmware protocol
# uses a fresh cryptographically random 12-byte nonce for every envelope.
# ============================================================================


def build_envelope_aad(
    sequence: int,
    timestamp_ms: int,
) -> bytes:
    return struct.pack(
        ">QQ",
        sequence,
        timestamp_ms,
    )


def encrypt_scadalgeria_payload(
    inner_message: list,
) -> bytes:
    encryption_key = require_session_key()

    sequence = reserve_next_sequence()
    timestamp_ms = current_unix_milliseconds()
    nonce = os.urandom(12)

    aad = build_envelope_aad(
        sequence,
        timestamp_ms,
    )

    plaintext = pack_messagepack(
        inner_message
    )

    ciphertext_and_tag = AESGCM(
        encryption_key
    ).encrypt(
        nonce,
        plaintext,
        aad,
    )

    ciphertext = ciphertext_and_tag[:-16]
    gcm_tag = ciphertext_and_tag[-16:]

    envelope = [
        API_KEY_ID,
        nonce,
        ciphertext,
        gcm_tag,
        sequence,
        timestamp_ms,
    ]

    return pack_messagepack(
        envelope
    )


def decrypt_scadalgeria_payload(
    envelope_payload: bytes,
):
    encryption_key = require_session_key()

    envelope = unpack_messagepack(
        envelope_payload
    )

    if (
        not isinstance(envelope, list)
        or len(envelope) != 6
    ):
        raise ValueError(
            "Malformed SCADALGERIA encrypted envelope"
        )

    key_id = envelope[0]
    nonce = envelope[1]
    ciphertext = envelope[2]
    gcm_tag = envelope[3]
    sequence = require_non_negative_integer(envelope[4])
    timestamp_ms = require_non_negative_integer(envelope[5])

    if key_id != API_KEY_ID:
        raise ValueError(
            "Encrypted envelope KeyId does not match this device credential"
        )

    if (
        not isinstance(nonce, bytes)
        or len(nonce) != 12
    ):
        raise ValueError(
            "Encrypted envelope nonce must be 12 bytes"
        )

    if not isinstance(ciphertext, bytes):
        raise ValueError(
            "Encrypted envelope ciphertext must be binary"
        )

    if (
        not isinstance(gcm_tag, bytes)
        or len(gcm_tag) != 16
    ):
        raise ValueError(
            "Encrypted envelope GCM tag must be 16 bytes"
        )

    aad = build_envelope_aad(
        sequence,
        timestamp_ms,
    )

    plaintext = AESGCM(
        encryption_key
    ).decrypt(
        nonce,
        ciphertext + gcm_tag,
        aad,
    )

    return unpack_messagepack(
        plaintext
    )


def publish_encrypted_message(
    client: mqtt.Client,
    topic: str,
    inner_message: list,
) -> None:
    encrypted_payload = encrypt_scadalgeria_payload(
        inner_message
    )

    publish_info = client.publish(
        topic,
        encrypted_payload,
        qos=1,
        retain=False,
    )

    if publish_info.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(
            f"MQTT publish failed locally: {publish_info.rc}"
        )


# ============================================================================
# STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
#
# TagFrameDto:
#
#   [0] Address
#   [1] ValNum
#   [2] ValStr
#   [3] TsUnixMs
#   [4] Quality
#
# This example sends a numeric 0.0 or 1.0 with Good quality (192).
# TsUnixMs=0 inside the frame asks the Direct Firmware path to stamp capture
# time after decrypt. The OUTER encrypted envelope timestamp remains current.
#
# TagFrameBatchDto:
#
#   [0] Frames
#   [1] TraceId
#   [2] SchemaVersion = 1
# ============================================================================


def publish_digital_input_telemetry(
    client: mqtt.Client,
) -> None:
    input_value = read_digital_input()

    tag_frame = [
        INPUT_TAG_ADDRESS,
        float(input_value),
        None,
        0,
        192,
    ]

    tag_frame_batch = [
        [tag_frame],
        None,
        1,
    ]

    publish_encrypted_message(
        client,
        TELEMETRY_TOPIC,
        tag_frame_batch,
    )

    print(
        f"Telemetry sent: {INPUT_TAG_ADDRESS}={input_value}"
    )


# ============================================================================
# STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
#
# CommandDto is a MessagePack positional array:
#
#   [0] Id
#   [1] TagAddress
#   [2] Value
#   [3] Timestamp
#   [4] ExpiryEpochSeconds
#   [5] LeasedUntil
#   [6] TraceId
#   [7] RequiresConfirmation
#   [8] Confirmed
#   [9] SchemaVersion = 2
#
# This snippet accepts only "do.output1" and only values 0/1.
# It rejects expired commands and honors the operator-confirmation requirement.
#
# CommandResultDto:
#
#   [0] CommandId
#   [1] Success
#   [2] ErrorMessage
#   [3] Data
#   [4] SchemaVersion = 1
# ============================================================================


def parse_output_bit(value) -> int:
    if value is True:
        return 1

    if value is False:
        return 0

    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value in (0, 1)
    ):
        return int(value)

    raise ValueError(
        "do.output1 accepts only 0 or 1"
    )


def execute_output_command(
    command: list,
) -> list:
    if len(command) != 10:
        raise ValueError(
            "CommandDto must contain exactly 10 fields"
        )

    command_id = command[0]
    tag_address = command[1]
    command_value = command[2]

    expiry_epoch_seconds = require_non_negative_integer(
        command[4]
    )

    requires_confirmation = command[7]
    confirmed = command[8]

    schema_version = require_non_negative_integer(
        command[9]
    )

    if (
        not isinstance(command_id, str)
        or not command_id
    ):
        raise ValueError(
            "Command Id must be a non-empty string"
        )

    if not isinstance(tag_address, str):
        raise ValueError(
            "Command TagAddress must be a string"
        )

    if (
        not isinstance(requires_confirmation, bool)
        or not isinstance(confirmed, bool)
    ):
        raise ValueError(
            "Command confirmation fields must be booleans"
        )

    if schema_version != 2:
        raise ValueError(
            f"Unsupported CommandDto schema version: {schema_version}"
        )

    if tag_address != OUTPUT_TAG_ADDRESS:
        raise ValueError(
            f"Unsupported command address: {tag_address}"
        )

    if expiry_epoch_seconds <= int(time.time()):
        raise ValueError(
            "Command expired"
        )

    if requires_confirmation and not confirmed:
        raise ValueError(
            "Command requires operator confirmation"
        )

    output_value = parse_output_bit(
        command_value
    )

    write_digital_output(
        output_value
    )

    print(
        f"Command applied: {OUTPUT_TAG_ADDRESS}={output_value}"
    )

    return [
        command_id,
        True,
        None,
        json.dumps(
            {"appliedValue": output_value}
        ),
        1,
    ]


def handle_scadalgeria_command(
    client: mqtt.Client,
    encrypted_payload: bytes,
) -> None:
    command = decrypt_scadalgeria_payload(
        encrypted_payload
    )

    if not isinstance(command, list):
        raise ValueError(
            "Decrypted command payload is not a MessagePack array"
        )

    if (
        not command
        or not isinstance(command[0], str)
        or not command[0]
    ):
        # Without a real CommandId there is nothing useful to correlate back
        # to the platform. Fail closed rather than inventing an identifier.
        raise ValueError(
            "Malformed command does not contain a valid CommandId"
        )

    command_id = command[0]

    cached_result = get_cached_command_result(
        command_id
    )

    if cached_result is not None:
        print(
            f"Command redelivery detected: {command_id}; returning cached result"
        )

        publish_encrypted_message(
            client,
            COMMAND_RESULT_TOPIC,
            cached_result,
        )

        return

    try:
        command_result = execute_output_command(
            command
        )
    except Exception as error:
        command_result = [
            command_id,
            False,
            str(error)[:256],
            None,
            1,
        ]

        print(
            f"Command rejected: {error}"
        )

    # Persist the final result before publishing it to the platform.
    remember_command_result(
        command_id,
        command_result,
    )

    publish_encrypted_message(
        client,
        COMMAND_RESULT_TOPIC,
        command_result,
    )


# ============================================================================
# STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
#
# Important reconnect rule:
#
#   MQTT reconnect != reuse the old authenticated session.
#
# On every reconnect we clear the old AES session key, subscribe only to the
# challenge topic, and repeat authentication. The durable outgoing Seq and
# command-result cache do NOT reset.
#
# Also note: MQTT PUBACK only proves transport-level progress. platform can still
# reject telemetry semantically because of tag/type/quality/range/replay/rate
# rules. Use platform readback/observability when validating an integration.
# ============================================================================


def on_connect(
    client,
    _userdata,
    _flags,
    reason_code,
    _properties,
) -> None:
    global challenge_subscription_message_id
    global command_subscription_message_id

    if reason_code.is_failure:
        print(
            f"MQTT CONNECT failed: {reason_code}"
        )

        return

    print(
        "MQTT connected; waiting for a fresh SCADALGERIA challenge"
    )

    clear_authenticated_session()
    challenge_subscription_message_id = None
    command_subscription_message_id = None

    subscribe_result, challenge_subscription_message_id = client.subscribe(
        AUTH_CHALLENGE_TOPIC,
        qos=1,
    )

    if subscribe_result != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(
            "Pre-auth challenge subscription failed locally"
        )


def on_disconnect(
    _client,
    _userdata,
    _disconnect_flags,
    reason_code,
    _properties,
) -> None:
    global challenge_subscription_message_id
    global command_subscription_message_id

    clear_authenticated_session()
    challenge_subscription_message_id = None
    command_subscription_message_id = None

    print(
        f"MQTT disconnected: {reason_code}; next connection must re-authenticate"
    )


def on_subscribe(
    _client,
    _userdata,
    message_id,
    reason_codes,
    _properties,
) -> None:
    exact_qos1_grant = (
        len(reason_codes) == 1
        and not reason_codes[0].is_failure
        and int(reason_codes[0].value) == 1
    )

    if message_id == challenge_subscription_message_id:
        if not exact_qos1_grant:
            clear_authenticated_session()
            raise RuntimeError(
                "The broker did not grant the authentication challenge subscription at QoS 1"
            )

        print(
            "Authentication challenge subscription granted at QoS 1"
        )
        return

    if message_id != command_subscription_message_id:
        return

    if not exact_qos1_grant:
        clear_authenticated_session()
        raise RuntimeError(
            "The broker did not grant the exact command subscription at QoS 1"
        )

    authenticated.set()

    print(
        "SCADALGERIA session authenticated; telemetry and commands are enabled"
    )


def on_message(
    client,
    _userdata,
    message,
) -> None:
    try:
        if message.topic == AUTH_CHALLENGE_TOPIC:
            authenticate_with_scadalgeria(
                client,
                message.payload,
            )

            return

        if (
            message.topic == COMMAND_TOPIC
            and authenticated.is_set()
        ):
            handle_scadalgeria_command(
                client,
                message.payload,
            )

    except Exception as error:
        # Do not print API_KEY_TOKEN, session_key, HMAC input, or plaintext
        # command material in production diagnostics.
        print(
            f"SCADALGERIA protocol error: {error}"
        )


mqtt_client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    client_id=CLIENT_ID,
    protocol=mqtt.MQTTv311,
    clean_session=True,
)

mqtt_client.username_pw_set(
    MQTT_USERNAME,
    password="",
)

# Paho's network loop can reconnect after an unexpected disconnect. Backoff
# prevents a broken device from hammering the MQTT service with a tight reconnect loop.
mqtt_client.reconnect_delay_set(
    min_delay=1,
    max_delay=30,
)

mqtt_client.on_connect = on_connect
mqtt_client.on_disconnect = on_disconnect
mqtt_client.on_subscribe = on_subscribe
mqtt_client.on_message = on_message

mqtt_client.connect(
    MQTT_HOST,
    MQTT_PORT,
    keepalive=60,
)

mqtt_client.loop_start()

try:
    if not authenticated.wait(timeout=20):
        raise TimeoutError(
            "SCADALGERIA authentication was not promoted within 20 seconds"
        )

    while True:
        # A reconnect clears this event. Telemetry pauses until the new
        # challenge/response flow and post-auth subscription complete.
        if not authenticated.wait(timeout=1.0):
            continue

        publish_digital_input_telemetry(
            mqtt_client
        )

        # One second is only the example cadence. The real client must obey
        # the telemetryPolicy in the copied connection configuration.
        time.sleep(1.0)

finally:
    mqtt_client.disconnect()
    mqtt_client.loop_stop()
    gpio_request.release()
