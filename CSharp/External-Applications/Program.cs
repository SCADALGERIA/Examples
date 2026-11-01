// SCADALGERIA Direct Firmware example — Raspberry Pi 5 / C# (.NET 10)
//
// This single source file demonstrates the complete Direct Firmware lifecycle:
//
//   BCM17 -> "di.input1" telemetry -> SCADALGERIA
//   BCM27 <- "do.output1" command  <- SCADALGERIA
//
// The example intentionally leaves the SCADALGERIA wire contract visible.
// MQTTnet, MessagePack-CSharp, .NET cryptography, and System.Device.Gpio do
// the generic work; the helpers below define the platform-specific protocol.


// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

using System.Buffers.Binary;
using System.Device.Gpio;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MessagePack;
using MQTTnet;
using MQTTnet.Formatter;
using MQTTnet.Protocol;


// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
//
// Save Connection → Copy firmware configuration → Copy JSON as
// `scadalgeria-connection.json`. The copied document is non-secret and is
// authoritative for broker, identity, topic templates, QoS, policies, and tags.
// Supply the API-key secret separately through SCADALGERIA_API_KEY.
// ============================================================================

static string RequiredSecret(string name)
{
    var value = Environment.GetEnvironmentVariable(name);
    if (string.IsNullOrWhiteSpace(value))
        throw new InvalidOperationException($"Missing required secret: {name}");
    return value;
}

static JsonElement RequiredObject(JsonElement parent, string name)
{
    if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Object)
        throw new InvalidOperationException($"Copied configuration field '{name}' must be an object");
    return value;
}

static string RequiredString(JsonElement parent, string name)
{
    if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
        throw new InvalidOperationException($"Copied configuration field '{name}' is missing or invalid");
    return value.GetString()!;
}

static string CreateUniqueClientId() =>
    $"scada-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}";

static string ResolveClientTopic(string template, string clientId)
{
    if (template.Split("{clientId}", StringSplitOptions.None).Length != 2)
        throw new InvalidOperationException("Authentication topic template must contain exactly one {clientId}");
    return template.Replace("{clientId}", clientId, StringComparison.Ordinal);
}

static void RequireBooleanTag(JsonElement root, string address, string direction)
{
    if (!root.TryGetProperty("tags", out var tags) || tags.ValueKind != JsonValueKind.Array)
        throw new InvalidOperationException("Copied configuration does not contain a tags array");

    var matches = tags.EnumerateArray()
        .Where(tag => tag.TryGetProperty("address", out var a) && a.GetString() == address)
        .ToArray();

    if (matches.Length != 1 ||
        RequiredString(matches[0], "dataType") != "Boolean" ||
        RequiredString(matches[0], "direction") != direction)
        throw new InvalidOperationException($"Tag '{address}' must exist exactly once as Boolean/{direction}");
}

const string InputTagAddress = "di.input1";
const string OutputTagAddress = "do.output1";

var configurationPath = Environment.GetEnvironmentVariable("SCADALGERIA_CONFIG_FILE")
    ?? "scadalgeria-connection.json";

using var configurationDocument = JsonDocument.Parse(
    File.ReadAllText(configurationPath)
);

var root = configurationDocument.RootElement;

if (RequiredString(root, "schema") != "scadalgeria.direct-firmware.connection" ||
    !root.TryGetProperty("schemaVersion", out var schemaVersion) || schemaVersion.GetInt32() != 1)
    throw new InvalidOperationException("Unsupported SCADALGERIA connection configuration schema");

var connection = RequiredObject(root, "connection");
var identity = RequiredObject(root, "identity");
var mqttConfiguration = RequiredObject(root, "mqtt");
var broker = RequiredObject(mqttConfiguration, "broker");
var topics = RequiredObject(mqttConfiguration, "topics");
var qos = RequiredObject(mqttConfiguration, "qos");
var authentication = RequiredObject(root, "authentication");
var encryption = RequiredObject(root, "encryption");
var kdf = RequiredObject(encryption, "sessionKeyDerivation");
var secretsContract = RequiredObject(root, "secrets");

if (!connection.TryGetProperty("enabled", out var enabled) || enabled.ValueKind != JsonValueKind.True)
    throw new InvalidOperationException("The copied Connection is disabled");
if (RequiredString(mqttConfiguration, "protocol") != "3.1.1" ||
    !mqttConfiguration.TryGetProperty("cleanSession", out var cleanSession) || cleanSession.ValueKind != JsonValueKind.True)
    throw new InvalidOperationException("This example requires MQTT 3.1.1 with cleanSession=true");
if (RequiredString(broker, "transport") != "tcp")
    throw new InvalidOperationException("Unsupported copied MQTT transport");
if (RequiredString(mqttConfiguration, "clientIdRequirement") != "unique-per-active-session")
    throw new InvalidOperationException("Unsupported clientIdRequirement");
if (qos.GetProperty("telemetry").GetInt32() != 1 || qos.GetProperty("commands").GetInt32() != 1 || qos.GetProperty("commandResults").GetInt32() != 1)
    throw new InvalidOperationException("This example requires copied telemetry/command/result QoS values of 1");
if (RequiredString(authentication, "scheme") != "HMAC-SHA256" || RequiredString(encryption, "scheme") != "AES-256-GCM")
    throw new InvalidOperationException("Unsupported authentication/encryption contract");
if (RequiredString(kdf, "algorithm") != "HKDF-SHA256" || RequiredString(kdf, "info") != "SCADA-ENC-v1")
    throw new InvalidOperationException("Unsupported session-key derivation contract");
if (!secretsContract.TryGetProperty("apiKeySecretIncluded", out var secretIncluded) || secretIncluded.ValueKind != JsonValueKind.False)
    throw new InvalidOperationException("Connection Copy JSON must never contain the API-key secret");

RequireBooleanTag(root, InputTagAddress, "Input");
RequireBooleanTag(root, OutputTagAddress, "Output");

var clientId = CreateUniqueClientId();

var configuration = new ScadalgeriaConfiguration
{
    Host = RequiredString(broker, "host"),
    Port = broker.GetProperty("port").GetInt32(),
    ClientId = clientId,
    MqttUsername = RequiredString(mqttConfiguration, "username"),
    ApiKeyId = RequiredString(identity, "keyId"),
    ApiKeyToken = RequiredSecret("SCADALGERIA_API_KEY"),
    AuthChallengeTopic = ResolveClientTopic(RequiredString(topics, "authenticationChallenge"), clientId),
    AuthResponseTopic = ResolveClientTopic(RequiredString(topics, "authenticationResponse"), clientId),
    TelemetryTopic = RequiredString(topics, "telemetry"),
    CommandsTopic = RequiredString(topics, "commands"),
    CommandResultTopic = RequiredString(topics, "commandResults"),
};


// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
//
// BCM17 -> active-low input with pull-up.
// BCM27 -> set-state digital output.
//
// Never drive an industrial load directly from a Raspberry Pi GPIO. Use the
// correct isolation/driver hardware for the actual field device.
// ============================================================================

using var gpio = new GpioController();

gpio.OpenPin(
    17,
    PinMode.InputPullUp
);

gpio.OpenPin(
    27,
    PinMode.Output
);

gpio.Write(
    27,
    PinValue.Low
);

int ReadDigitalInput()
{
    return gpio.Read(17) == PinValue.Low
        ? 1
        : 0;
}

void WriteDigitalOutput(int value)
{
    gpio.Write(
        27,
        value == 1
            ? PinValue.High
            : PinValue.Low
    );
}


// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
//
// The device->platform envelope Seq is durable replay/order state. It must not
// reset on MQTT reconnect, process restart, host reboot, or power loss.
//
// Persist the incremented value before returning it. If the process crashes,
// a skipped number is safe; reusing an old number is not.
//
// Final command results are cached by CommandDto.Id so a normal at-least-once
// redelivery can return the same result without applying the output again.
// ============================================================================

var stateStore = DeviceStateStore.Load(
    ".scadalgeria-state.json"
);

var stateLock = new object();

ulong ReserveNextSequence()
{
    lock (stateLock)
    {
        stateStore.Sequence++;
        stateStore.Save();

        return stateStore.Sequence;
    }
}

CommandResultDto? GetCachedCommandResult(string commandId)
{
    lock (stateLock)
    {
        stateStore.CommandResults.TryGetValue(
            commandId,
            out var result
        );

        return result;
    }
}

void RememberCommandResult(
    string commandId,
    CommandResultDto result
)
{
    lock (stateLock)
    {
        stateStore.CommandResults[commandId] = result;
        stateStore.TrimCommandResults(64);
        stateStore.Save();
    }
}


// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
//
// MQTT CONNECT does not mean the Direct Firmware session is authenticated.
//
// The application-layer flow is:
//
//   CONNECT MQTT 3.1.1 / CleanSession=true
//       ↓
//   subscribe ONLY to authChallenge
//       ↓
//   receive [ServerNonce, ExpiresAtUnixMs]
//       ↓
//   create 16-byte ClientNonce
//       ↓
//   HMAC-SHA256(ServerNonce || ClientNonce || UTF8(ClientId))
//       ↓
//   publish [ClientNonce, Auth]
//       ↓
//   derive 32-byte HKDF-SHA256 session key
//       ↓
//   subscribe to the exact commands topic
//       ↓
//   GrantedQoS1 proves promotion for this bidirectional example
//
// Every reconnect discards the old session key and repeats authentication.
// ============================================================================

var sessionLock = new object();
byte[]? sessionKey = null;
var authenticationState = new AuthenticationState();

var messagePackOptions = MessagePackSerializerOptions.Standard
    .WithSecurity(MessagePackSecurity.UntrustedData);

ulong CurrentUnixMilliseconds()
{
    return checked(
        (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
    );
}

void SetSessionKey(byte[] value)
{
    lock (sessionLock)
    {
        sessionKey = value.ToArray();
    }
}

void ClearAuthenticatedSession()
{
    lock (sessionLock)
    {
        sessionKey = null;
    }

    authenticationState.IsAuthenticated = false;
}

byte[] RequireSessionKey()
{
    lock (sessionLock)
    {
        return sessionKey?.ToArray()
            ?? throw new InvalidOperationException(
                "SCADALGERIA session is not authenticated"
            );
    }
}

byte[] DeriveSessionKey(
    byte[] serverNonce,
    byte[] clientNonce
)
{
    var derivedKey = new byte[32];

    var salt = serverNonce
        .Concat(clientNonce)
        .ToArray();

    HKDF.DeriveKey(
        HashAlgorithmName.SHA256,
        Encoding.UTF8.GetBytes(configuration.ApiKeyToken),
        derivedKey,
        salt,
        Encoding.UTF8.GetBytes("SCADA-ENC-v1")
    );

    return derivedKey;
}

byte[] BuildAuthenticationProof(
    byte[] serverNonce,
    byte[] clientNonce
)
{
    var proofInput = serverNonce
        .Concat(clientNonce)
        .Concat(
            Encoding.UTF8.GetBytes(configuration.ClientId)
        )
        .ToArray();

    return HMACSHA256.HashData(
        Encoding.UTF8.GetBytes(configuration.ApiKeyToken),
        proofInput
    );
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
// Nonce != Seq. The nonce protects AES-GCM uniqueness inside the current
// session; Seq is durable replay/order identity across sessions.
// ============================================================================

byte[] BuildEnvelopeAad(
    ulong sequence,
    ulong timestampMs
)
{
    var aad = new byte[16];

    BinaryPrimitives.WriteUInt64BigEndian(
        aad.AsSpan(0, 8),
        sequence
    );

    BinaryPrimitives.WriteUInt64BigEndian(
        aad.AsSpan(8, 8),
        timestampMs
    );

    return aad;
}

byte[] EncryptScadalgeriaPayload<T>(T innerMessage)
{
    var encryptionKey = RequireSessionKey();

    var sequence = ReserveNextSequence();
    var timestampMs = CurrentUnixMilliseconds();
    var nonce = RandomNumberGenerator.GetBytes(12);

    var plaintext = MessagePackSerializer.Serialize(
        innerMessage,
        messagePackOptions
    );

    var ciphertext = new byte[plaintext.Length];
    var gcmTag = new byte[16];

    using var aesGcm = new AesGcm(
        encryptionKey,
        tagSizeInBytes: 16
    );

    aesGcm.Encrypt(
        nonce,
        plaintext,
        ciphertext,
        gcmTag,
        BuildEnvelopeAad(
            sequence,
            timestampMs
        )
    );

    var envelope = new AesGcmEnvelopeDto
    {
        KeyId = configuration.ApiKeyId,
        Nonce = nonce,
        Ciphertext = ciphertext,
        GcmTag = gcmTag,
        Seq = sequence,
        TsUnixMs = timestampMs,
    };

    return MessagePackSerializer.Serialize(
        envelope,
        messagePackOptions
    );
}

T DecryptScadalgeriaPayload<T>(
    ReadOnlyMemory<byte> envelopePayload
)
{
    var envelope = MessagePackSerializer.Deserialize<AesGcmEnvelopeDto>(
        envelopePayload,
        messagePackOptions
    );

    if (envelope.KeyId != configuration.ApiKeyId)
    {
        throw new CryptographicException(
            "Encrypted envelope KeyId does not match this credential"
        );
    }

    if (envelope.Nonce.Length != 12)
    {
        throw new CryptographicException(
            "Encrypted envelope nonce must be 12 bytes"
        );
    }

    if (envelope.GcmTag.Length != 16)
    {
        throw new CryptographicException(
            "Encrypted envelope GCM tag must be 16 bytes"
        );
    }

    var plaintext = new byte[envelope.Ciphertext.Length];

    using var aesGcm = new AesGcm(
        RequireSessionKey(),
        tagSizeInBytes: 16
    );

    aesGcm.Decrypt(
        envelope.Nonce,
        envelope.Ciphertext,
        envelope.GcmTag,
        plaintext,
        BuildEnvelopeAad(
            envelope.Seq,
            envelope.TsUnixMs
        )
    );

    return MessagePackSerializer.Deserialize<T>(
        plaintext,
        messagePackOptions
    );
}


// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
// ============================================================================

var mqttClient = new MqttClientFactory()
    .CreateMqttClient();

var mqttOptions = new MqttClientOptionsBuilder()
    .WithTcpServer(
        configuration.Host,
        configuration.Port
    )
    .WithClientId(configuration.ClientId)
    .WithCredentials(
        configuration.MqttUsername,
        ""
    )
    .WithProtocolVersion(MqttProtocolVersion.V311)
    .WithCleanSession()
    .Build();

async Task SubscribeExactQos1Async(string topic)
{
    var subscribeOptions = new MqttClientSubscribeOptionsBuilder()
        .WithTopicFilter(
            filter => filter
                .WithTopic(topic)
                .WithQualityOfServiceLevel(
                    MqttQualityOfServiceLevel.AtLeastOnce
                )
        )
        .Build();

    var result = await mqttClient.SubscribeAsync(
        subscribeOptions
    );

    if (
        result.Items.Count != 1
        || result.Items.First().ResultCode
            != MqttClientSubscribeResultCode.GrantedQoS1
    )
    {
        throw new InvalidOperationException(
            $"The broker did not grant QoS 1 subscription: {topic}"
        );
    }
}

async Task PublishRawQos1Async(
    string topic,
    byte[] payload
)
{
    var message = new MqttApplicationMessageBuilder()
        .WithTopic(topic)
        .WithPayload(payload)
        .WithQualityOfServiceLevel(
            MqttQualityOfServiceLevel.AtLeastOnce
        )
        .WithRetainFlag(false)
        .Build();

    await mqttClient.PublishAsync(message);
}

async Task PublishEncryptedAsync<T>(
    string topic,
    T innerMessage
)
{
    await PublishRawQos1Async(
        topic,
        EncryptScadalgeriaPayload(innerMessage)
    );
}

async Task PublishDigitalInputTelemetryAsync()
{
    var inputValue = ReadDigitalInput();

    var batch = new TagFrameBatchDto
    {
        Frames =
        [
            new TagFrameDto
            {
                Address = InputTagAddress,
                ValNum = inputValue,
                ValStr = null,

                // Direct Firmware convention: inner frame timestamp 0 asks
                // the platform to stamp capture time after decrypt.
                TsUnixMs = 0,
                Quality = 192,
            },
        ],
        TraceId = null,
        SchemaVersion = 1,
    };

    await PublishEncryptedAsync(
        configuration.TelemetryTopic,
        batch
    );

    Console.WriteLine(
        $"Telemetry sent: {InputTagAddress}={inputValue}"
    );
}


// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
// ============================================================================

async Task AuthenticateWithScadalgeriaAsync(
    ReadOnlyMemory<byte> payload
)
{
    var challenge = MessagePackSerializer.Deserialize<MqttAuthChallengeDto>(
        payload,
        messagePackOptions
    );

    if (challenge.ServerNonce.Length != 16)
    {
        throw new CryptographicException(
            "Authentication ServerNonce must be 16 bytes"
        );
    }

    if (
        CurrentUnixMilliseconds()
        >= checked((ulong)challenge.ExpiresAtUnixMs)
    )
    {
        throw new CryptographicException(
            "SCADALGERIA authentication challenge expired"
        );
    }

    var clientNonce = RandomNumberGenerator.GetBytes(16);

    var authenticationProof = BuildAuthenticationProof(
        challenge.ServerNonce,
        clientNonce
    );

    var newSessionKey = DeriveSessionKey(
        challenge.ServerNonce,
        clientNonce
    );

    SetSessionKey(newSessionKey);

    var response = new MqttAuthResponseDto
    {
        ClientNonce = clientNonce,
        Auth = authenticationProof,
    };

    await PublishRawQos1Async(
        configuration.AuthResponseTopic,
        MessagePackSerializer.Serialize(
            response,
            messagePackOptions
        )
    );

    // There is no custom AUTH_OK packet. The exact post-auth command
    // subscription provides a concrete promotion gate for this example.
    await SubscribeExactQos1Async(
        configuration.CommandsTopic
    );

    authenticationState.IsAuthenticated = true;

    Console.WriteLine(
        "SCADALGERIA session authenticated; telemetry and commands are enabled"
    );
}

static int ParseOutputBit(object? value)
{
    return value switch
    {
        bool boolean => boolean ? 1 : 0,

        byte number when number <= 1 => number,
        sbyte number when number is 0 or 1 => number,
        short number when number is 0 or 1 => number,
        ushort number when number <= 1 => number,
        int number when number is 0 or 1 => number,
        uint number when number <= 1 => (int)number,
        long number when number is 0 or 1 => (int)number,
        ulong number when number <= 1 => (int)number,
        float number when number is 0 or 1 => (int)number,
        double number when number is 0 or 1 => (int)number,

        _ => throw new InvalidOperationException(
            "do.output1 accepts only 0 or 1"
        ),
    };
}

async Task HandleScadalgeriaCommandAsync(
    ReadOnlyMemory<byte> encryptedPayload
)
{
    var command = DecryptScadalgeriaPayload<CommandDto>(
        encryptedPayload
    );

    if (string.IsNullOrWhiteSpace(command.Id))
    {
        throw new InvalidOperationException(
            "Command Id must not be empty"
        );
    }

    var cachedResult = GetCachedCommandResult(
        command.Id
    );

    if (cachedResult is not null)
    {
        Console.WriteLine(
            $"Command redelivery detected: {command.Id}; returning cached result"
        );

        await PublishEncryptedAsync(
            configuration.CommandResultTopic,
            cachedResult
        );

        return;
    }

    CommandResultDto finalResult;

    try
    {
        if (command.SchemaVersion != 2)
        {
            throw new InvalidOperationException(
                $"Unsupported CommandDto schema version: {command.SchemaVersion}"
            );
        }

        if (command.TagAddress != OutputTagAddress)
        {
            throw new InvalidOperationException(
                $"Unsupported command address: {command.TagAddress}"
            );
        }

        if (
            command.Expiry
            <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        )
        {
            throw new InvalidOperationException(
                "Command expired"
            );
        }

        if (
            command.RequiresConfirmation
            && !command.Confirmed
        )
        {
            throw new InvalidOperationException(
                "Command requires operator confirmation"
            );
        }

        var outputValue = ParseOutputBit(
            command.Value
        );

        WriteDigitalOutput(
            outputValue
        );

        finalResult = new CommandResultDto
        {
            CommandId = command.Id,
            Success = true,
            ErrorMessage = null,
            Data = JsonSerializer.Serialize(
                new { appliedValue = outputValue }
            ),
            SchemaVersion = 1,
        };

        Console.WriteLine(
            $"Command applied: {OutputTagAddress}={outputValue}"
        );
    }
    catch (Exception commandError)
    {
        var boundedError = commandError.Message.Length <= 256
            ? commandError.Message
            : commandError.Message[..256];

        finalResult = new CommandResultDto
        {
            CommandId = command.Id,
            Success = false,
            ErrorMessage = boundedError,
            Data = null,
            SchemaVersion = 1,
        };

        Console.Error.WriteLine(
            $"Command rejected: {commandError.Message}"
        );
    }

    RememberCommandResult(
        command.Id,
        finalResult
    );

    await PublishEncryptedAsync(
        configuration.CommandResultTopic,
        finalResult
    );
}


// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
//
// On every new connection we clear the previous app-layer session and
// subscribe only to authChallenge. Telemetry pauses until promotion succeeds.
// ============================================================================

mqttClient.ConnectedAsync += async _ =>
{
    ClearAuthenticatedSession();

    Console.WriteLine(
        "MQTT connected; waiting for a fresh SCADALGERIA challenge"
    );

    await SubscribeExactQos1Async(
        configuration.AuthChallengeTopic
    );
};

mqttClient.ApplicationMessageReceivedAsync += async eventArgs =>
{
    try
    {
        var topic = eventArgs.ApplicationMessage.Topic;
        var payload = eventArgs.ApplicationMessage.Payload;

        if (topic == configuration.AuthChallengeTopic)
        {
            await AuthenticateWithScadalgeriaAsync(
                payload
            );

            return;
        }

        if (
            topic == configuration.CommandsTopic
            && authenticationState.IsAuthenticated
        )
        {
            await HandleScadalgeriaCommandAsync(
                payload
            );
        }
    }
    catch (Exception protocolError)
    {
        // Never print the API token, HMAC material, or session key.
        Console.Error.WriteLine(
            $"SCADALGERIA protocol error: {protocolError.Message}"
        );
    }
};

var reconnectGate = new SemaphoreSlim(1, 1);

mqttClient.DisconnectedAsync += async _ =>
{
    ClearAuthenticatedSession();

    if (!await reconnectGate.WaitAsync(0))
    {
        return;
    }

    try
    {
        var delay = TimeSpan.FromSeconds(1);

        while (!mqttClient.IsConnected)
        {
            try
            {
                await Task.Delay(delay);
                await mqttClient.ConnectAsync(mqttOptions);
            }
            catch (Exception reconnectError)
            {
                Console.Error.WriteLine(
                    $"MQTT reconnect failed: {reconnectError.Message}"
                );

                var nextSeconds = Math.Min(
                    delay.TotalSeconds * 2,
                    30
                );

                delay = TimeSpan.FromSeconds(
                    nextSeconds
                );
            }
        }
    }
    finally
    {
        reconnectGate.Release();
    }
};

await mqttClient.ConnectAsync(
    mqttOptions
);

var authenticationDeadline =
    DateTimeOffset.UtcNow
    + TimeSpan.FromSeconds(20);

while (
    !authenticationState.IsAuthenticated
    && DateTimeOffset.UtcNow < authenticationDeadline
)
{
    await Task.Delay(25);
}

if (!authenticationState.IsAuthenticated)
{
    throw new TimeoutException(
        "SCADALGERIA authentication was not promoted within 20 seconds"
    );
}

while (true)
{
    if (!authenticationState.IsAuthenticated)
    {
        await Task.Delay(250);
        continue;
    }

    await PublishDigitalInputTelemetryAsync();

    // One second is only this example's cadence. A real client must obey the
    // telemetryPolicy in the copied connection configuration.
    await Task.Delay(1000);
}


// ============================================================================
// DTOs — NUMERIC MESSAGEPACK KEYS MATCH THE SCADALGERIA WIRE FORMAT
// ============================================================================

sealed class AuthenticationState
{
    // MQTTnet callbacks and the telemetry loop can run concurrently.
    // A volatile field makes the small authentication gate explicit without
    // mixing it into the session-key lock used for key material.
    public volatile bool IsAuthenticated;
}

sealed class ScadalgeriaConfiguration
{
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required string ClientId { get; init; }
    public required string MqttUsername { get; init; }
    public required string ApiKeyId { get; init; }
    public required string ApiKeyToken { get; init; }
    public required string AuthChallengeTopic { get; init; }
    public required string AuthResponseTopic { get; init; }
    public required string TelemetryTopic { get; init; }
    public required string CommandsTopic { get; init; }
    public required string CommandResultTopic { get; init; }
}

[MessagePackObject]
sealed class MqttAuthChallengeDto
{
    [Key(0)]
    public byte[] ServerNonce { get; set; } = [];

    [Key(1)]
    public long ExpiresAtUnixMs { get; set; }
}

[MessagePackObject]
sealed class MqttAuthResponseDto
{
    [Key(0)]
    public byte[] ClientNonce { get; set; } = [];

    [Key(1)]
    public byte[] Auth { get; set; } = [];
}

[MessagePackObject]
sealed class AesGcmEnvelopeDto
{
    [Key(0)]
    public string KeyId { get; set; } = "";

    [Key(1)]
    public byte[] Nonce { get; set; } = [];

    [Key(2)]
    public byte[] Ciphertext { get; set; } = [];

    [Key(3)]
    public byte[] GcmTag { get; set; } = [];

    [Key(4)]
    public ulong Seq { get; set; }

    [Key(5)]
    public ulong TsUnixMs { get; set; }
}

[MessagePackObject]
sealed class TagFrameDto
{
    [Key(0)]
    public string Address { get; set; } = "";

    [Key(1)]
    public double? ValNum { get; set; }

    [Key(2)]
    public string? ValStr { get; set; }

    [Key(3)]
    public long TsUnixMs { get; set; }

    [Key(4)]
    public int Quality { get; set; }
}

[MessagePackObject]
sealed class TagFrameBatchDto
{
    [Key(0)]
    public List<TagFrameDto> Frames { get; set; } = [];

    [Key(1)]
    public string? TraceId { get; set; }

    [Key(2)]
    public int SchemaVersion { get; set; } = 1;
}

[MessagePackObject]
sealed class CommandDto
{
    [Key(0)]
    public string Id { get; set; } = "";

    [Key(1)]
    public string TagAddress { get; set; } = "";

    [Key(2)]
    public object? Value { get; set; }

    [Key(3)]
    public DateTime Timestamp { get; set; }

    [Key(4)]
    public long Expiry { get; set; }

    [Key(5)]
    public long? LeasedUntil { get; set; }

    [Key(6)]
    public string? TraceId { get; set; }

    [Key(7)]
    public bool RequiresConfirmation { get; set; }

    [Key(8)]
    public bool Confirmed { get; set; }

    [Key(9)]
    public int SchemaVersion { get; set; } = 2;
}

[MessagePackObject]
sealed class CommandResultDto
{
    [Key(0)]
    public string CommandId { get; set; } = "";

    [Key(1)]
    public bool Success { get; set; }

    [Key(2)]
    public string? ErrorMessage { get; set; }

    [Key(3)]
    public string? Data { get; set; }

    [Key(4)]
    public int SchemaVersion { get; set; } = 1;
}


// ============================================================================
// DURABLE STATE STORE USED BY THE EXAMPLE
// ============================================================================

sealed class DeviceStateStore
{
    public ulong Sequence { get; set; }

    public Dictionary<string, CommandResultDto> CommandResults { get; set; }
        = [];

    [System.Text.Json.Serialization.JsonIgnore]
    public string FilePath { get; private set; } = "";

    public static DeviceStateStore Load(string path)
    {
        DeviceStateStore state;

        if (File.Exists(path))
        {
            state = JsonSerializer.Deserialize<DeviceStateStore>(
                File.ReadAllText(path)
            ) ?? new DeviceStateStore();
        }
        else
        {
            state = new DeviceStateStore();
        }

        state.FilePath = path;

        return state;
    }

    public void Save()
    {
        var temporaryPath = FilePath + ".tmp";

        File.WriteAllText(
            temporaryPath,
            JsonSerializer.Serialize(this)
        );

        File.Move(
            temporaryPath,
            FilePath,
            overwrite: true
        );
    }

    public void TrimCommandResults(int maximum)
    {
        while (CommandResults.Count > maximum)
        {
            var oldestKey = CommandResults.Keys.First();
            CommandResults.Remove(oldestKey);
        }
    }
}
