// SCADALGERIA Direct Firmware example — Raspberry Pi 5 / Rust
//
// Complete Direct Firmware flow:
//
//   BCM17 -> "di.input1" telemetry -> SCADALGERIA
//   BCM27 <- "do.output1" command  <- SCADALGERIA
//
// This is a readable protocol excerpt, not a complete Cargo project. The
// companion README lists the exact crate versions used by the snippet.


// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
    Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rmpv::{
    decode::read_value,
    encode::write_value,
    Value,
};
use rumqttc::{
    mqttbytes::v4::SubscribeReasonCode,
    Client,
    Event,
    Incoming,
    MqttOptions,
    QoS,
    RecvTimeoutError,
};
use rppal::gpio::{
    Gpio,
    InputPin,
    OutputPin,
};
use serde_json::Value as JsonValue;
use sha2::{
    Digest,
    Sha256,
};
use std::{
    env,
    error::Error,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};


type HmacSha256 = Hmac<Sha256>;
type AnyError = Box<dyn Error + Send + Sync>;


// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
//
// Save Connection → Copy firmware configuration → Copy JSON as
// `scadalgeria-connection.json`. Supply SCADALGERIA_API_KEY separately.
// ============================================================================

#[derive(Debug)]
struct Configuration {
    host: &'static str,
    port: u16,
    client_id: &'static str,
    mqtt_username: &'static str,
    api_key_id: &'static str,
    api_key_token: &'static str,
    auth_challenge_topic: &'static str,
    auth_response_topic: &'static str,
    telemetry_topic: &'static str,
    commands_topic: &'static str,
    command_result_topic: &'static str,
}

fn leak(value: String) -> &'static str { Box::leak(value.into_boxed_str()) }

fn required_secret(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing required secret: {name}"))
}

fn json_string<'a>(root: &'a JsonValue, pointer: &str) -> &'a str {
    root.pointer(pointer).and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("missing/invalid copied configuration field: {pointer}"))
}

fn json_bool(root: &JsonValue, pointer: &str) -> bool {
    root.pointer(pointer).and_then(JsonValue::as_bool)
        .unwrap_or_else(|| panic!("missing/invalid copied configuration field: {pointer}"))
}

fn json_u64(root: &JsonValue, pointer: &str) -> u64 {
    root.pointer(pointer).and_then(JsonValue::as_u64)
        .unwrap_or_else(|| panic!("missing/invalid copied configuration field: {pointer}"))
}

fn create_unique_client_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    let mut result = String::from("scada-");
    for byte in bytes { result.push_str(&format!("{byte:02x}")); }
    result
}

fn resolve_client_topic(template: &str, client_id: &str) -> String {
    if template.matches("{clientId}").count() != 1 {
        panic!("authentication topic template must contain exactly one {{clientId}}");
    }
    template.replace("{clientId}", client_id)
}

fn require_boolean_tag(root: &JsonValue, address: &str, direction: &str) {
    let tags = root.get("tags").and_then(JsonValue::as_array).expect("copied configuration has no tags array");
    let matches: Vec<_> = tags.iter().filter(|tag| tag.get("address").and_then(JsonValue::as_str) == Some(address)).collect();
    if matches.len() != 1 || matches[0].get("dataType").and_then(JsonValue::as_str) != Some("Boolean") || matches[0].get("direction").and_then(JsonValue::as_str) != Some(direction) {
        panic!("tag {address} must exist exactly once as Boolean/{direction}");
    }
}

static CONFIGURATION: LazyLock<Configuration> = LazyLock::new(|| {
    let path = env::var("SCADALGERIA_CONFIG_FILE").unwrap_or_else(|_| "scadalgeria-connection.json".to_string());
    let text = fs::read_to_string(path).expect("unable to read copied SCADALGERIA connection configuration");
    let root: JsonValue = serde_json::from_str(&text).expect("copied SCADALGERIA connection configuration is not valid JSON");

    if json_string(&root, "/schema") != "scadalgeria.direct-firmware.connection" || json_u64(&root, "/schemaVersion") != 1 { panic!("unsupported connection configuration schema"); }
    if !json_bool(&root, "/connection/enabled") { panic!("the copied Connection is disabled"); }
    if json_string(&root, "/mqtt/protocol") != "3.1.1" || !json_bool(&root, "/mqtt/cleanSession") { panic!("MQTT 3.1.1 with cleanSession=true is required"); }
    if json_string(&root, "/mqtt/broker/transport") != "tcp" { panic!("unsupported copied MQTT transport"); }
    if json_string(&root, "/mqtt/clientIdRequirement") != "unique-per-active-session" { panic!("unsupported clientIdRequirement"); }
    if json_u64(&root, "/mqtt/qos/telemetry") != 1 || json_u64(&root, "/mqtt/qos/commands") != 1 || json_u64(&root, "/mqtt/qos/commandResults") != 1 { panic!("copied telemetry/command/result QoS must be 1"); }
    if json_string(&root, "/authentication/scheme") != "HMAC-SHA256" || json_string(&root, "/encryption/scheme") != "AES-256-GCM" { panic!("unsupported authentication/encryption contract"); }
    if json_string(&root, "/encryption/sessionKeyDerivation/algorithm") != "HKDF-SHA256" || json_string(&root, "/encryption/sessionKeyDerivation/info") != "SCADA-ENC-v1" { panic!("unsupported session-key derivation contract"); }
    if json_bool(&root, "/secrets/apiKeySecretIncluded") { panic!("Connection Copy JSON must never contain the API-key secret"); }

    require_boolean_tag(&root, "di.input1", "Input");
    require_boolean_tag(&root, "do.output1", "Output");

    let client_id = create_unique_client_id();
    Configuration {
        host: leak(json_string(&root, "/mqtt/broker/host").to_string()),
        port: json_u64(&root, "/mqtt/broker/port") as u16,
        client_id: leak(client_id.clone()),
        mqtt_username: leak(json_string(&root, "/mqtt/username").to_string()),
        api_key_id: leak(json_string(&root, "/identity/keyId").to_string()),
        api_key_token: leak(required_secret("SCADALGERIA_API_KEY")),
        auth_challenge_topic: leak(resolve_client_topic(json_string(&root, "/mqtt/topics/authenticationChallenge"), &client_id)),
        auth_response_topic: leak(resolve_client_topic(json_string(&root, "/mqtt/topics/authenticationResponse"), &client_id)),
        telemetry_topic: leak(json_string(&root, "/mqtt/topics/telemetry").to_string()),
        commands_topic: leak(json_string(&root, "/mqtt/topics/commands").to_string()),
        command_result_topic: leak(json_string(&root, "/mqtt/topics/commandResults").to_string()),
    }
});

const INPUT_TAG_ADDRESS: &str = "di.input1";
const OUTPUT_TAG_ADDRESS: &str = "do.output1";


// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
//
// BCM17 is an active-low switch input with pull-up.
// BCM27 is the set-state output controlled by "do.output1".
//
// Never connect an industrial load directly to Raspberry Pi GPIO.
// ============================================================================

fn initialize_digital_io() -> Result<(InputPin, OutputPin), AnyError> {
    let gpio = Gpio::new()?;

    let input = gpio
        .get(17)?
        .into_input_pullup();

    let output = gpio
        .get(27)?
        .into_output_low();

    Ok((input, output))
}

fn read_digital_input(input: &InputPin) -> i64 {
    if input.is_low() {
        1
    } else {
        0
    }
}

fn write_digital_output(
    output: &mut OutputPin,
    value: i64,
) {
    if value == 1 {
        output.set_high();
    } else {
        output.set_low();
    }
}


// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
//
// Seq survives MQTT reconnects and device/process restarts. The example writes
// the incremented value before using it. Skipping a value is safe; reusing an
// old value can be rejected as replay.
//
// CommandResultDto bytes are stored by a SHA-256 hash of CommandDto.Id so a
// normal redelivery can return the same result without reapplying the output.
// ============================================================================

const SEQUENCE_FILE: &str = ".scadalgeria-seq";
const RESULTS_DIRECTORY: &str = ".scadalgeria-results";
const MAX_CACHED_RESULTS: usize = 64;

fn reserve_next_sequence() -> Result<u64, AnyError> {
    let path = Path::new(SEQUENCE_FILE);

    let current = fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let next = current
        .checked_add(1)
        .ok_or("sequence exhausted")?;

    let temporary_path = Path::new(".scadalgeria-seq.tmp");

    fs::write(
        temporary_path,
        next.to_string(),
    )?;

    fs::rename(
        temporary_path,
        path,
    )?;

    Ok(next)
}

fn command_result_path(command_id: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(command_id.as_bytes());

    let digest = hasher.finalize();

    let file_name: String = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    PathBuf::from(RESULTS_DIRECTORY)
        .join(file_name)
}

fn get_cached_command_result(command_id: &str) -> Option<Vec<u8>> {
    fs::read(
        command_result_path(command_id),
    )
    .ok()
}

fn remember_command_result(
    command_id: &str,
    result: &[u8],
) -> Result<(), AnyError> {
    fs::create_dir_all(
        RESULTS_DIRECTORY,
    )?;

    let result_path = command_result_path(
        command_id,
    );

    let temporary_path = result_path.with_extension("tmp");

    fs::write(
        &temporary_path,
        result,
    )?;

    fs::rename(
        temporary_path,
        result_path,
    )?;

    prune_command_result_cache()?;

    Ok(())
}

fn prune_command_result_cache() -> Result<(), AnyError> {
    let mut files: Vec<_> = fs::read_dir(RESULTS_DIRECTORY)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .collect();

    if files.len() <= MAX_CACHED_RESULTS {
        return Ok(());
    }

    files.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(UNIX_EPOCH)
    });

    while files.len() > MAX_CACHED_RESULTS {
        let oldest = files.remove(0);
        let _ = fs::remove_file(oldest.path());
    }

    Ok(())
}


// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
// ============================================================================

fn current_unix_milliseconds() -> Result<u64, AnyError> {
    Ok(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
    )
}

fn current_unix_seconds() -> Result<u64, AnyError> {
    Ok(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs(),
    )
}

fn pack_messagepack(value: &Value) -> Result<Vec<u8>, AnyError> {
    let mut buffer = Vec::new();

    write_value(
        &mut buffer,
        value,
    )?;

    Ok(buffer)
}

fn unpack_messagepack(bytes: &[u8]) -> Result<Value, AnyError> {
    Ok(
        read_value(
            &mut Cursor::new(bytes),
        )?,
    )
}

fn require_array<'a>(
    value: &'a Value,
    field_name: &str,
) -> Result<&'a Vec<Value>, AnyError> {
    value
        .as_array()
        .ok_or_else(|| format!("{field_name} must be a MessagePack array").into())
}

fn require_binary(
    value: &Value,
    field_name: &str,
) -> Result<Vec<u8>, AnyError> {
    match value {
        Value::Binary(bytes) => Ok(bytes.clone()),
        _ => Err(format!("{field_name} must be MessagePack binary").into()),
    }
}

fn require_string(
    value: &Value,
    field_name: &str,
) -> Result<String, AnyError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{field_name} must be a string").into())
}

fn require_unsigned_integer(
    value: &Value,
    field_name: &str,
) -> Result<u64, AnyError> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }

    if let Some(number) = value.as_i64() {
        if number >= 0 {
            return Ok(number as u64);
        }
    }

    Err(
        format!("{field_name} must be a non-negative integer").into(),
    )
}

fn require_boolean(
    value: &Value,
    field_name: &str,
) -> Result<bool, AnyError> {
    value
        .as_bool()
        .ok_or_else(|| format!("{field_name} must be a boolean").into())
}

fn derive_session_key(
    server_nonce: &[u8],
    client_nonce: &[u8],
) -> Result<[u8; 32], AnyError> {
    let mut salt = Vec::with_capacity(32);
    salt.extend_from_slice(server_nonce);
    salt.extend_from_slice(client_nonce);

    let hkdf = Hkdf::<Sha256>::new(
        Some(&salt),
        CONFIGURATION.api_key_token.as_bytes(),
    );

    let mut session_key = [0u8; 32];

    hkdf.expand(
        b"SCADA-ENC-v1",
        &mut session_key,
    )?;

    Ok(session_key)
}

fn build_authentication_proof(
    server_nonce: &[u8],
    client_nonce: &[u8],
) -> Result<Vec<u8>, AnyError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(
        CONFIGURATION.api_key_token.as_bytes(),
    )?;

    mac.update(server_nonce);
    mac.update(client_nonce);
    mac.update(CONFIGURATION.client_id.as_bytes());

    Ok(
        mac.finalize()
            .into_bytes()
            .to_vec(),
    )
}


// ============================================================================
// STEP 6 OF 9 — MESSAGEPACK DTOs AND AES-256-GCM ENVELOPE
//
// Envelope:
//
//   [ KeyId, Nonce:bin12, Ciphertext, GcmTag:bin16, Seq, TsUnixMs ]
//
// AAD:
//
//   UInt64BE(Seq) || UInt64BE(TsUnixMs)
// ============================================================================

fn build_envelope_aad(
    sequence: u64,
    timestamp_ms: u64,
) -> [u8; 16] {
    let mut aad = [0u8; 16];

    aad[0..8].copy_from_slice(
        &sequence.to_be_bytes(),
    );

    aad[8..16].copy_from_slice(
        &timestamp_ms.to_be_bytes(),
    );

    aad
}

fn encrypt_scadalgeria_payload(
    session_key: &[u8; 32],
    inner_message: &Value,
) -> Result<Vec<u8>, AnyError> {
    let sequence = reserve_next_sequence()?;
    let timestamp_ms = current_unix_milliseconds()?;

    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    let plaintext = pack_messagepack(
        inner_message,
    )?;

    let cipher = Aes256Gcm::new_from_slice(
        session_key,
    )?;

    let aad = build_envelope_aad(
        sequence,
        timestamp_ms,
    );

    let ciphertext_and_tag = cipher.encrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: &plaintext,
            aad: &aad,
        },
    )?;

    let ciphertext_length = ciphertext_and_tag.len() - 16;

    let ciphertext = ciphertext_and_tag[..ciphertext_length]
        .to_vec();

    let gcm_tag = ciphertext_and_tag[ciphertext_length..]
        .to_vec();

    let envelope = Value::Array(vec![
        CONFIGURATION.api_key_id.into(),
        Value::Binary(nonce.to_vec()),
        Value::Binary(ciphertext),
        Value::Binary(gcm_tag),
        sequence.into(),
        timestamp_ms.into(),
    ]);

    pack_messagepack(
        &envelope,
    )
}

fn decrypt_scadalgeria_payload(
    session_key: &[u8; 32],
    envelope_payload: &[u8],
) -> Result<Value, AnyError> {
    let envelope = unpack_messagepack(
        envelope_payload,
    )?;

    let fields = require_array(
        &envelope,
        "AesGcmEnvelopeDto",
    )?;

    if fields.len() != 6 {
        return Err(
            "AesGcmEnvelopeDto must contain exactly 6 fields".into(),
        );
    }

    let key_id = require_string(
        &fields[0],
        "KeyId",
    )?;

    let nonce = require_binary(
        &fields[1],
        "Nonce",
    )?;

    let ciphertext = require_binary(
        &fields[2],
        "Ciphertext",
    )?;

    let gcm_tag = require_binary(
        &fields[3],
        "GcmTag",
    )?;

    let sequence = require_unsigned_integer(
        &fields[4],
        "Seq",
    )?;

    let timestamp_ms = require_unsigned_integer(
        &fields[5],
        "TsUnixMs",
    )?;

    if key_id != CONFIGURATION.api_key_id {
        return Err(
            "Encrypted envelope KeyId does not match this credential".into(),
        );
    }

    if nonce.len() != 12 {
        return Err(
            "Encrypted envelope nonce must be 12 bytes".into(),
        );
    }

    if gcm_tag.len() != 16 {
        return Err(
            "Encrypted envelope GCM tag must be 16 bytes".into(),
        );
    }

    let mut ciphertext_and_tag = ciphertext;
    ciphertext_and_tag.extend_from_slice(&gcm_tag);

    let cipher = Aes256Gcm::new_from_slice(
        session_key,
    )?;

    let aad = build_envelope_aad(
        sequence,
        timestamp_ms,
    );

    let plaintext = cipher.decrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: &ciphertext_and_tag,
            aad: &aad,
        },
    )?;

    unpack_messagepack(
        &plaintext,
    )
}

fn publish_encrypted_message(
    client: &mut Client,
    session_key: &[u8; 32],
    topic: &str,
    inner_message: &Value,
) -> Result<(), AnyError> {
    let encrypted_payload = encrypt_scadalgeria_payload(
        session_key,
        inner_message,
    )?;

    client.publish(
        topic,
        QoS::AtLeastOnce,
        false,
        encrypted_payload,
    )?;

    Ok(())
}


// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
// ============================================================================

fn authenticate_with_scadalgeria(
    client: &mut Client,
    challenge_payload: &[u8],
) -> Result<[u8; 32], AnyError> {
    let challenge = unpack_messagepack(
        challenge_payload,
    )?;

    let fields = require_array(
        &challenge,
        "MqttAuthChallengeDto",
    )?;

    if fields.len() != 2 {
        return Err(
            "MqttAuthChallengeDto must contain exactly 2 fields".into(),
        );
    }

    let server_nonce = require_binary(
        &fields[0],
        "ServerNonce",
    )?;

    let expires_at_ms = require_unsigned_integer(
        &fields[1],
        "ExpiresAtUnixMs",
    )?;

    if server_nonce.len() != 16 {
        return Err(
            "Authentication ServerNonce must be 16 bytes".into(),
        );
    }

    if current_unix_milliseconds()? >= expires_at_ms {
        return Err(
            "SCADALGERIA authentication challenge expired".into(),
        );
    }

    let mut client_nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut client_nonce);

    let authentication_proof = build_authentication_proof(
        &server_nonce,
        &client_nonce,
    )?;

    let session_key = derive_session_key(
        &server_nonce,
        &client_nonce,
    )?;

    let auth_response = Value::Array(vec![
        Value::Binary(client_nonce.to_vec()),
        Value::Binary(authentication_proof),
    ]);

    client.publish(
        CONFIGURATION.auth_response_topic,
        QoS::AtLeastOnce,
        false,
        pack_messagepack(&auth_response)?,
    )?;

    client.subscribe(
        CONFIGURATION.commands_topic,
        QoS::AtLeastOnce,
    )?;

    Ok(session_key)
}

fn publish_digital_input_telemetry(
    client: &mut Client,
    session_key: &[u8; 32],
    input: &InputPin,
) -> Result<(), AnyError> {
    let input_value = read_digital_input(input);

    let tag_frame = Value::Array(vec![
        INPUT_TAG_ADDRESS.into(),
        (input_value as f64).into(),
        Value::Nil,
        0.into(),
        192.into(),
    ]);

    let tag_frame_batch = Value::Array(vec![
        Value::Array(vec![tag_frame]),
        Value::Nil,
        1.into(),
    ]);

    publish_encrypted_message(
        client,
        session_key,
        CONFIGURATION.telemetry_topic,
        &tag_frame_batch,
    )?;

    println!(
        "Telemetry sent: {INPUT_TAG_ADDRESS}={input_value}",
    );

    Ok(())
}


// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
// ============================================================================

fn parse_output_bit(value: &Value) -> Result<i64, AnyError> {
    if let Some(boolean) = value.as_bool() {
        return Ok(if boolean { 1 } else { 0 });
    }

    if let Some(number) = value.as_i64() {
        if number == 0 || number == 1 {
            return Ok(number);
        }
    }

    if let Some(number) = value.as_u64() {
        if number <= 1 {
            return Ok(number as i64);
        }
    }

    Err(
        "do.output1 accepts only 0 or 1".into(),
    )
}

fn build_command_result(
    command_id: &str,
    success: bool,
    error_message: Option<String>,
    data: Option<String>,
) -> Value {
    Value::Array(vec![
        command_id.into(),
        success.into(),
        error_message
            .map(Value::from)
            .unwrap_or(Value::Nil),
        data
            .map(Value::from)
            .unwrap_or(Value::Nil),
        1.into(),
    ])
}

fn handle_scadalgeria_command(
    client: &mut Client,
    session_key: &[u8; 32],
    output: &mut OutputPin,
    encrypted_payload: &[u8],
) -> Result<(), AnyError> {
    let command = decrypt_scadalgeria_payload(
        session_key,
        encrypted_payload,
    )?;

    let fields = require_array(
        &command,
        "CommandDto",
    )?;

    if fields.len() != 10 {
        return Err(
            "CommandDto must contain exactly 10 fields".into(),
        );
    }

    let command_id = require_string(
        &fields[0],
        "Command Id",
    )?;

    if command_id.is_empty() {
        return Err(
            "Command Id must not be empty".into(),
        );
    }

    if let Some(cached_bytes) = get_cached_command_result(&command_id) {
        let cached_result = unpack_messagepack(
            &cached_bytes,
        )?;

        println!(
            "Command redelivery detected: {command_id}; returning cached result",
        );

        publish_encrypted_message(
            client,
            session_key,
            CONFIGURATION.command_result_topic,
            &cached_result,
        )?;

        return Ok(());
    }

    let operation_result = (|| -> Result<Value, AnyError> {
        let tag_address = require_string(
            &fields[1],
            "TagAddress",
        )?;

        let expiry_epoch_seconds = require_unsigned_integer(
            &fields[4],
            "Expiry",
        )?;

        let requires_confirmation = require_boolean(
            &fields[7],
            "RequiresConfirmation",
        )?;

        let confirmed = require_boolean(
            &fields[8],
            "Confirmed",
        )?;

        let schema_version = require_unsigned_integer(
            &fields[9],
            "SchemaVersion",
        )?;

        if schema_version != 2 {
            return Err(
                "unsupported CommandDto schema version".into(),
            );
        }

        if tag_address != OUTPUT_TAG_ADDRESS {
            return Err(
                format!("unsupported command address: {tag_address}").into(),
            );
        }

        if expiry_epoch_seconds <= current_unix_seconds()? {
            return Err(
                "command expired".into(),
            );
        }

        if requires_confirmation && !confirmed {
            return Err(
                "command requires operator confirmation".into(),
            );
        }

        let output_value = parse_output_bit(
            &fields[2],
        )?;

        write_digital_output(
            output,
            output_value,
        );

        println!(
            "Command applied: {OUTPUT_TAG_ADDRESS}={output_value}",
        );

        Ok(
            build_command_result(
                &command_id,
                true,
                None,
                Some(format!(
                    "{{\"appliedValue\":{output_value}}}"
                )),
            ),
        )
    })();

    let final_result = match operation_result {
        Ok(result) => result,
        Err(error) => {
            let bounded_error: String = error
                .to_string()
                .chars()
                .take(256)
                .collect();

            eprintln!(
                "Command rejected: {bounded_error}",
            );

            build_command_result(
                &command_id,
                false,
                Some(bounded_error),
                None,
            )
        }
    };

    let final_result_bytes = pack_messagepack(
        &final_result,
    )?;

    remember_command_result(
        &command_id,
        &final_result_bytes,
    )?;

    publish_encrypted_message(
        client,
        session_key,
        CONFIGURATION.command_result_topic,
        &final_result,
    )?;

    Ok(())
}


// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
//
// recv_timeout() is used instead of a blocking iterator so the process can
// continue sending periodic telemetry even when no MQTT packet arrives.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingSubscription {
    AuthenticationChallenge,
    Commands,
}

fn main() -> Result<(), AnyError> {
    let (input, mut output) = initialize_digital_io()?;

    let mut mqtt_options = MqttOptions::new(
        CONFIGURATION.client_id,
        CONFIGURATION.host,
        CONFIGURATION.port,
    );

    mqtt_options.set_clean_session(true);
    mqtt_options.set_credentials(
        CONFIGURATION.mqtt_username,
        "",
    );
    mqtt_options.set_keep_alive(
        Duration::from_secs(60),
    );

    let (mut client, mut connection) = Client::new(
        mqtt_options,
        16,
    );

    let mut session_key: Option<[u8; 32]> = None;
    let mut authenticated = false;
    let mut pending_subscription: Option<PendingSubscription> = None;

    let mut last_telemetry = Instant::now();

    loop {
        match connection.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                match event {
                    Event::Incoming(Incoming::ConnAck(_)) => {
                        // New MQTT connection = new SCADALGERIA auth session.
                        session_key = None;
                        authenticated = false;
                        pending_subscription = Some(
                            PendingSubscription::AuthenticationChallenge,
                        );

                        client.subscribe(
                            CONFIGURATION.auth_challenge_topic,
                            QoS::AtLeastOnce,
                        )?;

                        println!(
                            "MQTT connected; waiting for a fresh SCADALGERIA challenge",
                        );
                    }

                    Event::Incoming(Incoming::Publish(publish))
                        if publish.topic == CONFIGURATION.auth_challenge_topic
                            && pending_subscription.is_none()
                            && !authenticated =>
                    {
                        let new_session_key = authenticate_with_scadalgeria(
                            &mut client,
                            &publish.payload,
                        )?;

                        session_key = Some(new_session_key);
                        pending_subscription = Some(
                            PendingSubscription::Commands,
                        );
                    }

                    Event::Incoming(Incoming::SubAck(suback))
                        if pending_subscription.is_some() =>
                    {
                        let exact_qos1_grant =
                            suback.return_codes.len() == 1
                            && matches!(
                                suback.return_codes[0],
                                SubscribeReasonCode::Success(QoS::AtLeastOnce)
                            );

                        if !exact_qos1_grant {
                            return Err(
                                "SCADALGERIA subscription was not granted at QoS 1".into(),
                            );
                        }

                        match pending_subscription.take() {
                            Some(PendingSubscription::AuthenticationChallenge) => {
                                println!(
                                    "Authentication challenge subscription granted at QoS 1",
                                );
                            }

                            Some(PendingSubscription::Commands) => {
                                authenticated = true;

                                println!(
                                    "SCADALGERIA session authenticated; telemetry and commands are enabled",
                                );
                            }

                            None => {}
                        }
                    }

                    Event::Incoming(Incoming::Publish(publish))
                        if publish.topic == CONFIGURATION.commands_topic
                            && authenticated =>
                    {
                        if let Some(key) = session_key.as_ref() {
                            if let Err(error) = handle_scadalgeria_command(
                                &mut client,
                                key,
                                &mut output,
                                &publish.payload,
                            ) {
                                eprintln!(
                                    "SCADALGERIA protocol error: {error}",
                                );
                            }
                        }
                    }

                    _ => {}
                }
            }

            Ok(Err(connection_error)) => {
                session_key = None;
                authenticated = false;
                pending_subscription = None;

                eprintln!(
                    "MQTT connection lost: {connection_error}; retrying with backoff",
                );

                std::thread::sleep(
                    Duration::from_secs(2),
                );
            }

            Err(RecvTimeoutError::Timeout) => {
                // Normal. The timeout exists so the telemetry timer can run.
            }

            Err(RecvTimeoutError::Disconnected) => {
                return Err(
                    "rumqttc request channel disconnected".into(),
                );
            }
        }

        if (
            authenticated
            && last_telemetry.elapsed() >= Duration::from_secs(1)
        ) {
            if let Some(key) = session_key.as_ref() {
                publish_digital_input_telemetry(
                    &mut client,
                    key,
                    &input,
                )?;

                last_telemetry = Instant::now();
            }
        }

        // One second is only the public example cadence. A production client
        // must obey the copied configuration telemetryPolicy.
    }
}
