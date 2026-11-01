"""
SCADALGERIA Direct Firmware example — ESP32 / MicroPython

Device flow:

    GPIO4  -> "di.input1" telemetry -> SCADALGERIA
    GPIO18 <- "do.output1" command  <- SCADALGERIA

This example uses:

    umqtt.simple          MQTT 3.1.1 transport
    umsgpack              MessagePack DTO arrays
    scada_crypto          tiny native adapter for HMAC/HKDF/AES-GCM

`scada_crypto` is documented in the companion README because stock MicroPython
builds do not expose all of the cryptographic primitives required by the current
SCADALGERIA Direct Firmware protocol.

The surrounding firmware must already have working network connectivity and a
reasonably synchronized UTC clock before this code reaches MQTT authentication.
"""


# ============================================================================
# STEP 1 OF 9 — IMPORTS AND TARGET NOTES
# ============================================================================

import os
import time
import ubinascii
import ujson
import esp32

from machine import Pin
from umqtt.simple import MQTTClient

import scada_crypto
import umsgpack


# ============================================================================
# STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
#
# Put Connection → Copy firmware configuration → Copy JSON at
# `/scadalgeria-connection.json` on the device filesystem.
# Store the API-key secret separately in ESP32 NVS namespace `scada_secret`,
# blob key `api_key`. The copied JSON itself must remain non-secret.
# ============================================================================

CONNECTION_CONFIG_FILE = "/scadalgeria-connection.json"
INPUT_TAG_ADDRESS = "di.input1"
OUTPUT_TAG_ADDRESS = "do.output1"


def load_api_key_secret():
    nvs = esp32.NVS("scada_secret")
    buffer = bytearray(512)
    try:
        length = nvs.get_blob("api_key", buffer)
    except OSError as exc:
        raise RuntimeError("SCADALGERIA API key is not provisioned in NVS") from exc
    secret = bytes(buffer[:length]).rstrip(b"\x00")
    if not secret:
        raise RuntimeError("SCADALGERIA API key in NVS is empty")
    return secret


def create_unique_client_id():
    return "scada-" + ubinascii.hexlify(os.urandom(8)).decode()


def resolve_client_topic(template, client_id):
    if template.count("{clientId}") != 1:
        raise RuntimeError("Authentication topic template must contain exactly one {clientId}")
    return template.replace("{clientId}", client_id)


def require_boolean_tag(manifest, address, direction):
    matches = [tag for tag in manifest.get("tags", ()) if tag.get("address") == address]
    if len(matches) != 1 or matches[0].get("dataType") != "Boolean" or matches[0].get("direction") != direction:
        raise RuntimeError("Tag %s must exist exactly once as Boolean/%s" % (address, direction))


def load_connection_configuration():
    with open(CONNECTION_CONFIG_FILE, "r") as config_file:
        manifest = ujson.load(config_file)

    if manifest.get("schema") != "scadalgeria.direct-firmware.connection" or manifest.get("schemaVersion") != 1:
        raise RuntimeError("Unsupported SCADALGERIA connection configuration schema")

    connection = manifest.get("connection", {})
    identity = manifest.get("identity", {})
    mqtt = manifest.get("mqtt", {})
    broker = mqtt.get("broker", {})
    topics = mqtt.get("topics", {})
    qos = mqtt.get("qos", {})
    authentication = manifest.get("authentication", {})
    encryption = manifest.get("encryption", {})
    kdf = encryption.get("sessionKeyDerivation", {})
    secrets = manifest.get("secrets", {})

    if connection.get("enabled") is not True:
        raise RuntimeError("The copied Connection is disabled")
    if mqtt.get("protocol") != "3.1.1" or mqtt.get("cleanSession") is not True:
        raise RuntimeError("MQTT 3.1.1 with cleanSession=true is required")
    if broker.get("transport") != "tcp":
        raise RuntimeError("Unsupported copied MQTT transport")
    if mqtt.get("clientIdRequirement") != "unique-per-active-session":
        raise RuntimeError("Unsupported clientIdRequirement")
    if qos.get("telemetry") != 1 or qos.get("commands") != 1 or qos.get("commandResults") != 1:
        raise RuntimeError("Copied telemetry/command/result QoS must be 1")
    if authentication.get("scheme") != "HMAC-SHA256" or encryption.get("scheme") != "AES-256-GCM":
        raise RuntimeError("Unsupported authentication/encryption contract")
    if kdf.get("algorithm") != "HKDF-SHA256" or kdf.get("info") != "SCADA-ENC-v1":
        raise RuntimeError("Unsupported session-key derivation contract")
    if secrets.get("apiKeySecretIncluded") is not False:
        raise RuntimeError("Connection Copy JSON must never contain the API-key secret")

    require_boolean_tag(manifest, INPUT_TAG_ADDRESS, "Input")
    require_boolean_tag(manifest, OUTPUT_TAG_ADDRESS, "Output")

    client_id = create_unique_client_id()
    return {
        "host": broker["host"],
        "port": int(broker["port"]),
        "client_id": client_id,
        "mqtt_username": mqtt["username"],
        "key_id": identity["keyId"],
        "auth_challenge_topic": resolve_client_topic(topics["authenticationChallenge"], client_id),
        "auth_response_topic": resolve_client_topic(topics["authenticationResponse"], client_id),
        "telemetry_topic": topics["telemetry"],
        "commands_topic": topics["commands"],
        "command_result_topic": topics["commandResults"],
    }


configuration = load_connection_configuration()
MQTT_HOST = configuration["host"]
MQTT_PORT = configuration["port"]
CLIENT_ID = configuration["client_id"].encode()
MQTT_USERNAME = configuration["mqtt_username"].encode()
API_KEY_ID = configuration["key_id"]
API_KEY_TOKEN = load_api_key_secret()
AUTH_CHALLENGE_TOPIC = configuration["auth_challenge_topic"].encode()
AUTH_RESPONSE_TOPIC = configuration["auth_response_topic"].encode()
TELEMETRY_TOPIC = configuration["telemetry_topic"].encode()
COMMAND_TOPIC = configuration["commands_topic"].encode()
COMMAND_RESULT_TOPIC = configuration["command_result_topic"].encode()


# ============================================================================
#
# STEP 3 OF 9 — LOCAL DIGITAL I/O
#
# GPIO4 is an active-low switch input with the ESP32 pull-up enabled.
# GPIO18 is the set-state digital output controlled by "do.output1".
#
# Use proper isolation/driver electronics for real field equipment.
# ============================================================================

INPUT_GPIO = 4
OUTPUT_GPIO = 18


digital_input = Pin(
    INPUT_GPIO,
    Pin.IN,
    Pin.PULL_UP,
)


digital_output = Pin(
    OUTPUT_GPIO,
    Pin.OUT,
    value=0,
)


def read_digital_input():
    """Return 1 when the active-low input is asserted, otherwise 0."""

    return 1 if digital_input.value() == 0 else 0


def write_digital_output(value):
    """Apply one already-validated 0/1 command to GPIO18."""

    digital_output.value(
        1 if value == 1 else 0
    )


# ============================================================================
# STEP 4 OF 9 — DURABLE DEVICE STATE
#
# The outgoing envelope Seq is replay/order state and must survive MQTT
# reconnects and ESP32 resets. Persist it before using it.
#
# CommandResultDto bytes are cached by CommandDto.Id so ordinary QoS-1
# redelivery can return the same result instead of reapplying the output.
# ============================================================================

STATE_FILE = "/.scadalgeria-state.json"
MAX_CACHED_RESULTS = 32


def load_device_state():
    try:
        with open(STATE_FILE, "r") as state_file:
            return ujson.load(state_file)
    except OSError:
        return {
            "seq": 0,
            "results": {},
        }


device_state = load_device_state()


def save_device_state():
    temporary_file = STATE_FILE + ".tmp"

    with open(temporary_file, "w") as state_file:
        ujson.dump(
            device_state,
            state_file,
        )

    try:
        os.remove(STATE_FILE)
    except OSError:
        pass

    os.rename(
        temporary_file,
        STATE_FILE,
    )


def reserve_next_sequence():
    device_state["seq"] += 1

    save_device_state()

    return device_state["seq"]


def get_cached_command_result(command_id):
    encoded = device_state["results"].get(command_id)

    if encoded is None:
        return None

    return ubinascii.unhexlify(encoded)


def remember_command_result(command_id, raw_result):
    results = device_state["results"]

    results[command_id] = ubinascii.hexlify(
        raw_result
    ).decode()

    while len(results) > MAX_CACHED_RESULTS:
        oldest_command_id = next(iter(results))
        results.pop(oldest_command_id)

    save_device_state()


# ============================================================================
# STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
#
# MicroPython ports historically differ in their epoch. Normalize time.time()
# to Unix seconds so the challenge expiry and envelope timestamp use Unix time.
#
# Authentication proof:
#
#   HMAC-SHA256(
#       key     = UTF8(fullApiKeyToken),
#       message = ServerNonce || ClientNonce || UTF8(ClientId)
#   )
#
# Session key:
#
#   HKDF-SHA256(
#       IKM    = UTF8(fullApiKeyToken),
#       salt   = ServerNonce || ClientNonce,
#       info   = UTF8("SCADA-ENC-v1"),
#       length = 32
#   )
# ============================================================================

# Some MicroPython ports use 2000-01-01 as epoch 0.
UNIX_EPOCH_OFFSET = (
    946684800
    if time.gmtime(0)[0] == 2000
    else 0
)

session_key = None
authenticated = False
mqtt_client = None


def current_unix_seconds():
    return int(time.time()) + UNIX_EPOCH_OFFSET


def current_unix_milliseconds():
    # A second-resolution RTC still produces a valid Unix-millisecond field.
    # Freshness is the important protocol property for this MCU example.
    return current_unix_seconds() * 1000


def require_non_negative_integer(value, field_name):
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    ):
        return value

    raise ValueError(
        field_name + " must be a non-negative integer"
    )


def uint64_big_endian(value):
    return require_non_negative_integer(
        value,
        "uint64 value",
    ).to_bytes(
        8,
        "big",
    )


def derive_session_key(server_nonce, client_nonce):
    return scada_crypto.hkdf_sha256(
        API_KEY_TOKEN,
        server_nonce + client_nonce,
        b"SCADA-ENC-v1",
        32,
    )


def build_authentication_proof(server_nonce, client_nonce):
    proof_message = (
        server_nonce
        + client_nonce
        + CLIENT_ID
    )

    return scada_crypto.hmac_sha256(
        API_KEY_TOKEN,
        proof_message,
    )


def clear_authenticated_session():
    global session_key
    global authenticated

    session_key = None
    authenticated = False


# ============================================================================
# STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
#
# AesGcmEnvelopeDto:
#
#   [ KeyId, Nonce:bin12, Ciphertext, GcmTag:bin16, Seq, TsUnixMs ]
#
# AAD:
#
#   UInt64BE(Seq) || UInt64BE(TsUnixMs)
#
# The SCADALGERIA Direct Firmware protocol uses a fresh random 12-byte nonce per envelope.
# Seq is separate durable replay/order state.
# ============================================================================


def encrypt_scadalgeria_payload(inner_message):
    if session_key is None:
        raise RuntimeError(
            "SCADALGERIA session is not authenticated"
        )

    sequence = reserve_next_sequence()
    timestamp_ms = current_unix_milliseconds()
    nonce = os.urandom(12)

    aad = (
        uint64_big_endian(sequence)
        + uint64_big_endian(timestamp_ms)
    )

    plaintext = umsgpack.dumps(
        inner_message
    )

    ciphertext, gcm_tag = scada_crypto.aes_gcm_encrypt(
        session_key,
        nonce,
        plaintext,
        aad,
    )

    return umsgpack.dumps([
        API_KEY_ID,
        nonce,
        ciphertext,
        gcm_tag,
        sequence,
        timestamp_ms,
    ])


def decrypt_scadalgeria_payload(envelope_payload):
    if session_key is None:
        raise RuntimeError(
            "SCADALGERIA session is not authenticated"
        )

    envelope = umsgpack.loads(
        envelope_payload
    )

    if (
        not isinstance(envelope, (list, tuple))
        or len(envelope) != 6
    ):
        raise ValueError(
            "AesGcmEnvelopeDto must contain exactly 6 fields"
        )

    key_id = envelope[0]
    nonce = envelope[1]
    ciphertext = envelope[2]
    gcm_tag = envelope[3]
    sequence = require_non_negative_integer(
        envelope[4],
        "Envelope Seq",
    )
    timestamp_ms = require_non_negative_integer(
        envelope[5],
        "Envelope TsUnixMs",
    )

    if key_id != API_KEY_ID:
        raise ValueError(
            "Encrypted envelope KeyId does not match this credential"
        )

    if len(nonce) != 12:
        raise ValueError(
            "Encrypted envelope nonce must be 12 bytes"
        )

    if len(gcm_tag) != 16:
        raise ValueError(
            "Encrypted envelope GCM tag must be 16 bytes"
        )

    aad = (
        uint64_big_endian(sequence)
        + uint64_big_endian(timestamp_ms)
    )

    plaintext = scada_crypto.aes_gcm_decrypt(
        session_key,
        nonce,
        ciphertext,
        gcm_tag,
        aad,
    )

    return umsgpack.loads(
        plaintext
    )


def publish_encrypted_message(topic, inner_message):
    encrypted_payload = encrypt_scadalgeria_payload(
        inner_message
    )

    mqtt_client.publish(
        topic,
        encrypted_payload,
        retain=False,
        qos=1,
    )


# ============================================================================
# STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
# ============================================================================


def authenticate_with_scadalgeria(challenge_payload):
    global session_key
    global authenticated

    challenge = umsgpack.loads(
        challenge_payload
    )

    if (
        not isinstance(challenge, (list, tuple))
        or len(challenge) != 2
    ):
        raise ValueError(
            "MqttAuthChallengeDto must contain exactly 2 fields"
        )

    server_nonce = challenge[0]
    expires_at_ms = require_non_negative_integer(
        challenge[1],
        "ExpiresAtUnixMs",
    )

    if (
        not isinstance(server_nonce, (bytes, bytearray))
        or len(server_nonce) != 16
    ):
        raise ValueError(
            "Authentication ServerNonce must be 16 bytes"
        )

    if current_unix_milliseconds() >= expires_at_ms:
        raise ValueError(
            "SCADALGERIA authentication challenge expired"
        )

    client_nonce = os.urandom(16)

    authentication_proof = build_authentication_proof(
        server_nonce,
        client_nonce,
    )

    session_key = derive_session_key(
        server_nonce,
        client_nonce,
    )

    auth_response = umsgpack.dumps([
        client_nonce,
        authentication_proof,
    ])

    mqtt_client.publish(
        AUTH_RESPONSE_TOPIC,
        auth_response,
        retain=False,
        qos=1,
    )

    # umqtt.simple.subscribe() waits for SUBACK and raises MQTTException when
    # the broker returns 0x80. This exact post-auth subscription is therefore
    # the promotion gate for the bidirectional example.
    mqtt_client.subscribe(
        COMMAND_TOPIC,
        qos=1,
    )

    authenticated = True

    print(
        "SCADALGERIA session authenticated; telemetry and commands are enabled"
    )


def build_digital_input_telemetry():
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

    return input_value, tag_frame_batch


def publish_digital_input_telemetry():
    input_value, tag_frame_batch = build_digital_input_telemetry()

    publish_encrypted_message(
        TELEMETRY_TOPIC,
        tag_frame_batch,
    )

    print(
        "Telemetry sent: %s=%d"
        % (INPUT_TAG_ADDRESS, input_value)
    )


# ============================================================================
# STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
# ============================================================================


def parse_output_bit(value):
    if isinstance(value, bool):
        return 1 if value else 0

    if value == 0 or value == 1:
        return int(value)

    raise ValueError(
        "do.output1 accepts only 0 or 1"
    )


def build_command_result(
    command_id,
    success,
    error_message=None,
    applied_value=None,
):
    result_data = None

    if success:
        result_data = (
            '{"appliedValue":%d}'
            % applied_value
        )

    return [
        command_id,
        success,
        error_message,
        result_data,
        1,
    ]


def handle_scadalgeria_command(encrypted_payload):
    command = decrypt_scadalgeria_payload(
        encrypted_payload
    )

    if (
        not isinstance(command, (list, tuple))
        or len(command) != 10
    ):
        raise ValueError(
            "CommandDto must contain exactly 10 fields"
        )

    command_id = command[0]
    tag_address = command[1]

    if (
        not isinstance(command_id, str)
        or not command_id
        or not isinstance(tag_address, str)
    ):
        raise ValueError(
            "Command identity is malformed"
        )

    cached_result = get_cached_command_result(
        command_id
    )

    if cached_result is not None:
        print(
            "Command redelivery detected: %s; returning cached result"
            % command_id
        )

        publish_encrypted_message(
            COMMAND_RESULT_TOPIC,
            umsgpack.loads(cached_result),
        )

        return

    try:
        schema_version = require_non_negative_integer(
            command[9],
            "Command SchemaVersion",
        )

        expiry_epoch_seconds = require_non_negative_integer(
            command[4],
            "Command Expiry",
        )

        if schema_version != 2:
            raise ValueError(
                "Unsupported CommandDto schema version"
            )

        if tag_address != OUTPUT_TAG_ADDRESS:
            raise ValueError(
                "Unsupported command address: " + tag_address
            )

        if expiry_epoch_seconds <= current_unix_seconds():
            raise ValueError(
                "Command expired"
            )

        if (
            not isinstance(command[7], bool)
            or not isinstance(command[8], bool)
        ):
            raise ValueError(
                "Command confirmation fields must be booleans"
            )

        requires_confirmation = command[7]
        confirmed = command[8]

        if requires_confirmation and not confirmed:
            raise ValueError(
                "Command requires operator confirmation"
            )

        output_value = parse_output_bit(
            command[2]
        )

        write_digital_output(
            output_value
        )

        final_result = build_command_result(
            command_id,
            True,
            applied_value=output_value,
        )

        print(
            "Command applied: %s=%d"
            % (OUTPUT_TAG_ADDRESS, output_value)
        )

    except Exception as command_error:
        final_result = build_command_result(
            command_id,
            False,
            error_message=str(command_error)[:256],
        )

        print(
            "Command rejected:",
            command_error,
        )

    raw_result = umsgpack.dumps(
        final_result
    )

    remember_command_result(
        command_id,
        raw_result,
    )

    publish_encrypted_message(
        COMMAND_RESULT_TOPIC,
        final_result,
    )


# ============================================================================
# STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
#
# umqtt.simple has no automatic reconnect supervisor. The example therefore
# reconnects explicitly. Every new TCP/MQTT connection clears the old session
# key and subscribes only to authChallenge before telemetry can resume.
# ============================================================================


def on_mqtt_message(topic, payload):
    try:
        if topic == AUTH_CHALLENGE_TOPIC:
            authenticate_with_scadalgeria(
                payload
            )

            return

        if (
            topic == COMMAND_TOPIC
            and authenticated
        ):
            handle_scadalgeria_command(
                payload
            )

    except Exception as protocol_error:
        # Never log the API token or AES session key.
        print(
            "SCADALGERIA protocol error:",
            protocol_error,
        )


def connect_mqtt_and_start_authentication():
    global mqtt_client

    clear_authenticated_session()

    mqtt_client = MQTTClient(
        CLIENT_ID,
        MQTT_HOST,
        port=MQTT_PORT,
        user=MQTT_USERNAME,
        password=b"",
        keepalive=60,
    )

    mqtt_client.set_callback(
        on_mqtt_message
    )

    # umqtt.simple speaks MQTT 3.1.1. CleanSession=true is mandatory for the
    # Direct Firmware protocol.
    mqtt_client.connect(
        clean_session=True
    )

    mqtt_client.subscribe(
        AUTH_CHALLENGE_TOPIC,
        qos=1,
    )

    print(
        "MQTT connected; waiting for a fresh SCADALGERIA challenge"
    )


reconnect_delay_seconds = 1
last_telemetry_ms = time.ticks_ms()

while True:
    try:
        if mqtt_client is None:
            connect_mqtt_and_start_authentication()

            reconnect_delay_seconds = 1

        # check_msg() returns immediately when no packet is waiting.
        mqtt_client.check_msg()

        if (
            authenticated
            and time.ticks_diff(
                time.ticks_ms(),
                last_telemetry_ms,
            ) >= 1000
        ):
            publish_digital_input_telemetry()

            last_telemetry_ms = time.ticks_ms()

            # One second is only the public example cadence. A production
            # device must obey the copied configuration telemetryPolicy.

        time.sleep_ms(10)

    except (OSError, RuntimeError) as connection_error:
        clear_authenticated_session()

        try:
            if mqtt_client is not None:
                mqtt_client.disconnect()
        except Exception:
            pass

        mqtt_client = None

        print(
            "MQTT connection/authentication failed:",
            connection_error,
        )

        time.sleep(
            reconnect_delay_seconds
        )

        reconnect_delay_seconds = min(
            reconnect_delay_seconds * 2,
            30,
        )
