// SCADALGERIA Direct Firmware example — Raspberry Pi 5 / Go
//
// Complete Direct Firmware flow:
//
//   GPIO17 -> "di.input1" telemetry -> SCADALGERIA
//   GPIO27 <- "do.output1" command  <- SCADALGERIA
//
// The example keeps the SCADALGERIA Direct Firmware protocol visible rather than hiding it
// behind an imaginary device SDK. Generic MQTT, MessagePack, crypto, and GPIO
// packages are used directly.

package main

// ============================================================================
// STEP 1 OF 9 — IMPORTS AND TARGET NOTES
// ============================================================================

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/warthog618/go-gpiocdev"
)

// ============================================================================
// STEP 2 OF 9 — CONNECTION COPY JSON + API KEY SECRET
//
// Save Connection → Copy firmware configuration → Copy JSON as
// `scadalgeria-connection.json`. The copied document is non-secret. The only
// secret input here is SCADALGERIA_API_KEY.
// ============================================================================

type ConnectionManifest struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schemaVersion"`
	Connection    struct {
		Enabled bool `json:"enabled"`
	} `json:"connection"`
	Identity struct {
		KeyID string `json:"keyId"`
	} `json:"identity"`
	MQTT struct {
		Protocol            string `json:"protocol"`
		CleanSession        bool   `json:"cleanSession"`
		ClientIDRequirement string `json:"clientIdRequirement"`
		Username            string `json:"username"`
		Broker              struct {
			Host      string `json:"host"`
			Port      int    `json:"port"`
			Transport string `json:"transport"`
		} `json:"broker"`
		Topics struct {
			AuthenticationChallenge string `json:"authenticationChallenge"`
			AuthenticationResponse  string `json:"authenticationResponse"`
			Telemetry               string `json:"telemetry"`
			Commands                string `json:"commands"`
			CommandResults          string `json:"commandResults"`
		} `json:"topics"`
		QoS struct {
			Telemetry      int `json:"telemetry"`
			Commands       int `json:"commands"`
			CommandResults int `json:"commandResults"`
		} `json:"qos"`
	} `json:"mqtt"`
	Authentication struct {
		Scheme string `json:"scheme"`
	} `json:"authentication"`
	Encryption struct {
		Scheme               string `json:"scheme"`
		SessionKeyDerivation struct {
			Algorithm string `json:"algorithm"`
			Info      string `json:"info"`
		} `json:"sessionKeyDerivation"`
	} `json:"encryption"`
	Tags []struct {
		Address   string `json:"address"`
		DataType  string `json:"dataType"`
		Direction string `json:"direction"`
	} `json:"tags"`
	Secrets struct {
		APIKeySecretIncluded bool `json:"apiKeySecretIncluded"`
	} `json:"secrets"`
}

type Configuration struct {
	Host               string
	Port               int
	ClientID           string
	MqttUsername       string
	ApiKeyID           string
	ApiKeyToken        string
	AuthChallengeTopic string
	AuthResponseTopic  string
	TelemetryTopic     string
	CommandsTopic      string
	CommandResultTopic string
	GPIOChip           string
}

const (
	inputTagAddress  = "di.input1"
	outputTagAddress = "do.output1"
)

func requiredSecret(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic("missing required secret: " + name)
	}
	return value
}

func environmentValueOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func createUniqueClientID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return "scada-" + hex.EncodeToString(bytes)
}

func resolveClientTopic(template, clientID string) string {
	if strings.Count(template, "{clientId}") != 1 {
		panic("authentication topic template must contain exactly one {clientId}")
	}
	return strings.Replace(template, "{clientId}", clientID, 1)
}

func requireBooleanTag(manifest ConnectionManifest, address, direction string) {
	count := 0
	for _, tag := range manifest.Tags {
		if tag.Address == address {
			count++
			if tag.DataType != "Boolean" || tag.Direction != direction {
				panic(fmt.Sprintf("tag %q must be Boolean/%s", address, direction))
			}
		}
	}
	if count != 1 {
		panic(fmt.Sprintf("copied configuration must contain exactly one tag %q", address))
	}
}

func loadConfiguration() Configuration {
	path := environmentValueOr("SCADALGERIA_CONFIG_FILE", "scadalgeria-connection.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var manifest ConnectionManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		panic(err)
	}

	if manifest.Schema != "scadalgeria.direct-firmware.connection" || manifest.SchemaVersion != 1 {
		panic("unsupported SCADALGERIA connection configuration schema")
	}
	if !manifest.Connection.Enabled {
		panic("the copied Connection is disabled")
	}
	if manifest.MQTT.Protocol != "3.1.1" || !manifest.MQTT.CleanSession {
		panic("MQTT 3.1.1 with cleanSession=true is required")
	}
	if manifest.MQTT.Broker.Transport != "tcp" {
		panic("unsupported copied MQTT transport")
	}
	if manifest.MQTT.ClientIDRequirement != "unique-per-active-session" {
		panic("unsupported clientIdRequirement")
	}
	if manifest.MQTT.QoS.Telemetry != 1 || manifest.MQTT.QoS.Commands != 1 || manifest.MQTT.QoS.CommandResults != 1 {
		panic("copied telemetry/command/result QoS must be 1")
	}
	if manifest.Authentication.Scheme != "HMAC-SHA256" || manifest.Encryption.Scheme != "AES-256-GCM" {
		panic("unsupported authentication/encryption contract")
	}
	if manifest.Encryption.SessionKeyDerivation.Algorithm != "HKDF-SHA256" || manifest.Encryption.SessionKeyDerivation.Info != "SCADA-ENC-v1" {
		panic("unsupported session-key derivation contract")
	}
	if manifest.Secrets.APIKeySecretIncluded {
		panic("Connection Copy JSON must never contain the API-key secret")
	}

	requireBooleanTag(manifest, inputTagAddress, "Input")
	requireBooleanTag(manifest, outputTagAddress, "Output")

	clientID := createUniqueClientID()
	return Configuration{
		Host:               manifest.MQTT.Broker.Host,
		Port:               manifest.MQTT.Broker.Port,
		ClientID:           clientID,
		MqttUsername:       manifest.MQTT.Username,
		ApiKeyID:           manifest.Identity.KeyID,
		ApiKeyToken:        requiredSecret("SCADALGERIA_API_KEY"),
		AuthChallengeTopic: resolveClientTopic(manifest.MQTT.Topics.AuthenticationChallenge, clientID),
		AuthResponseTopic:  resolveClientTopic(manifest.MQTT.Topics.AuthenticationResponse, clientID),
		TelemetryTopic:     manifest.MQTT.Topics.Telemetry,
		CommandsTopic:      manifest.MQTT.Topics.Commands,
		CommandResultTopic: manifest.MQTT.Topics.CommandResults,
		GPIOChip:           environmentValueOr("SCADALGERIA_GPIO_CHIP", "/dev/gpiochip0"),
	}
}

var configuration = loadConfiguration()

const INPUT_TAG_ADDRESS = inputTagAddress
const OUTPUT_TAG_ADDRESS = outputTagAddress

// ============================================================================
//
// STEP 3 OF 9 — LOCAL DIGITAL I/O
//
// GPIO17 is an active-low switch input with a pull-up.
// GPIO27 is the output controlled by "do.output1".
//
// The example uses the Linux GPIO character-device API via go-gpiocdev.
// Never connect an industrial load directly to a Raspberry Pi GPIO.
// ============================================================================

func initializeDigitalIO() (
	*gpiocdev.Line,
	*gpiocdev.Line,
) {
	inputLine, err := gpiocdev.RequestLine(
		configuration.GPIOChip,
		17,
		gpiocdev.AsInput,
		gpiocdev.WithPullUp,
		gpiocdev.WithConsumer("scadalgeria-example"),
	)

	must(err)

	outputLine, err := gpiocdev.RequestLine(
		configuration.GPIOChip,
		27,
		gpiocdev.AsOutput(0),
		gpiocdev.WithConsumer("scadalgeria-example"),
	)

	if err != nil {
		_ = inputLine.Close()
		panic(err)
	}

	return inputLine, outputLine
}

func readDigitalInput(inputLine *gpiocdev.Line) int {
	rawValue, err := inputLine.Value()
	must(err)

	// Switch to ground means asserted=1.
	if rawValue == 0 {
		return 1
	}

	return 0
}

func writeDigitalOutput(
	outputLine *gpiocdev.Line,
	value int,
) error {
	return outputLine.SetValue(value)
}

// ============================================================================
// STEP 4 OF 9 — DURABLE DEVICE STATE
//
// Seq must survive MQTT reconnects, process restarts, and host reboot.
// The incremented value is written before it is returned to the caller.
//
// Final CommandResultDto payloads are stored by CommandDto.Id so ordinary
// at-least-once redelivery does not reapply the same set-state output.
// ============================================================================

type DeviceState struct {
	Sequence uint64            `json:"seq"`
	Results  map[string]string `json:"results"`
}

const deviceStatePath = ".scadalgeria-state.json"
const maximumCachedResults = 64

var deviceStateLock sync.Mutex
var deviceState = loadDeviceState()

func loadDeviceState() DeviceState {
	rawState, err := os.ReadFile(deviceStatePath)

	if err != nil {
		return DeviceState{
			Results: map[string]string{},
		}
	}

	var state DeviceState

	if json.Unmarshal(rawState, &state) != nil {
		panic("cannot decode SCADALGERIA durable state")
	}

	if state.Results == nil {
		state.Results = map[string]string{}
	}

	return state
}

func saveDeviceStateLocked() {
	rawState, err := json.Marshal(deviceState)
	must(err)

	temporaryPath := deviceStatePath + ".tmp"

	must(
		os.WriteFile(
			temporaryPath,
			rawState,
			0o600,
		),
	)

	must(
		os.Rename(
			temporaryPath,
			deviceStatePath,
		),
	)
}

func reserveNextSequence() uint64 {
	deviceStateLock.Lock()
	defer deviceStateLock.Unlock()

	deviceState.Sequence++

	saveDeviceStateLocked()

	return deviceState.Sequence
}

func getCachedCommandResult(
	commandID string,
) ([]any, bool) {
	deviceStateLock.Lock()
	encodedResult, found := deviceState.Results[commandID]
	deviceStateLock.Unlock()

	if !found {
		return nil, false
	}

	rawResult, err := base64.StdEncoding.DecodeString(
		encodedResult,
	)
	must(err)

	var result []any
	must(
		msgpack.Unmarshal(
			rawResult,
			&result,
		),
	)

	return result, true
}

func rememberCommandResult(
	commandID string,
	result []any,
) {
	rawResult, err := msgpack.Marshal(result)
	must(err)

	deviceStateLock.Lock()
	defer deviceStateLock.Unlock()

	deviceState.Results[commandID] =
		base64.StdEncoding.EncodeToString(rawResult)

	for len(deviceState.Results) > maximumCachedResults {
		for oldestID := range deviceState.Results {
			delete(
				deviceState.Results,
				oldestID,
			)
			break
		}
	}

	saveDeviceStateLocked()
}

// ============================================================================
// STEP 5 OF 9 — AUTHENTICATION CRYPTOGRAPHY AND SESSION STATE
// ============================================================================

var sessionLock sync.RWMutex
var sessionKey []byte
var authenticated atomic.Bool

var outputLine *gpiocdev.Line

func currentUnixMilliseconds() uint64 {
	return uint64(
		time.Now().UnixMilli(),
	)
}

func setSessionKey(newKey []byte) {
	sessionLock.Lock()
	defer sessionLock.Unlock()

	sessionKey = append(
		[]byte(nil),
		newKey...,
	)
}

func clearAuthenticatedSession() {
	sessionLock.Lock()
	sessionKey = nil
	sessionLock.Unlock()

	authenticated.Store(false)
}

func requireSessionKey() []byte {
	sessionLock.RLock()
	defer sessionLock.RUnlock()

	if len(sessionKey) != 32 {
		panic("SCADALGERIA session is not authenticated")
	}

	return append(
		[]byte(nil),
		sessionKey...,
	)
}

func deriveSessionKey(
	serverNonce []byte,
	clientNonce []byte,
) []byte {
	salt := make(
		[]byte,
		0,
		len(serverNonce)+len(clientNonce),
	)

	salt = append(salt, serverNonce...)
	salt = append(salt, clientNonce...)

	key, err := hkdf.Key(
		sha256.New,
		[]byte(configuration.ApiKeyToken),
		salt,
		"SCADA-ENC-v1",
		32,
	)

	must(err)

	return key
}

func buildAuthenticationProof(
	serverNonce []byte,
	clientNonce []byte,
) []byte {
	mac := hmac.New(
		sha256.New,
		[]byte(configuration.ApiKeyToken),
	)

	_, _ = mac.Write(serverNonce)
	_, _ = mac.Write(clientNonce)
	_, _ = mac.Write([]byte(configuration.ClientID))

	return mac.Sum(nil)
}

func subscribeExactQos1(
	client mqtt.Client,
	topic string,
	handler mqtt.MessageHandler,
) {
	// Subscribe() returns only the generic Token interface. Paho uses the
	// concrete *SubscribeToken for SUBACK details, including the granted QoS.
	// SCADALGERIA requests QoS 1 and this example refuses a downgraded grant.
	token := client.Subscribe(
		topic,
		1,
		handler,
	)

	token.Wait()
	must(token.Error())

	subscribeToken, ok := token.(*mqtt.SubscribeToken)
	if !ok {
		panic("Paho did not return a SubscribeToken for SUBSCRIBE")
	}

	grantedQos, present := subscribeToken.Result()[topic]
	if !present || grantedQos != 1 {
		panic(fmt.Sprintf(
			"broker did not grant QoS 1 for %s (granted=%d, present=%t)",
			topic,
			grantedQos,
			present,
		))
	}
}

func authenticateWithScadalgeria(
	client mqtt.Client,
	challengePayload []byte,
) {
	var challenge []any

	must(
		msgpack.Unmarshal(
			challengePayload,
			&challenge,
		),
	)

	if len(challenge) != 2 {
		panic("MqttAuthChallengeDto must contain exactly 2 fields")
	}

	serverNonce := requireBytes(
		challenge[0],
		"ServerNonce",
	)

	expiresAtUnixMs := requireUnsignedInteger(
		challenge[1],
		"ExpiresAtUnixMs",
	)

	if len(serverNonce) != 16 {
		panic("Authentication ServerNonce must be 16 bytes")
	}

	if currentUnixMilliseconds() >= expiresAtUnixMs {
		panic("SCADALGERIA authentication challenge expired")
	}

	clientNonce := make([]byte, 16)

	_, err := rand.Read(clientNonce)
	must(err)

	authenticationProof := buildAuthenticationProof(
		serverNonce,
		clientNonce,
	)

	setSessionKey(
		deriveSessionKey(
			serverNonce,
			clientNonce,
		),
	)

	authResponse, err := msgpack.Marshal(
		[]any{
			clientNonce,
			authenticationProof,
		},
	)
	must(err)

	publishToken := client.Publish(
		configuration.AuthResponseTopic,
		1,
		false,
		authResponse,
	)

	publishToken.Wait()
	must(publishToken.Error())

	// There is no custom AUTH_OK packet. A successful QoS-1 SUBACK for the
	// exact post-auth command topic is the promotion proof used by this
	// bidirectional example.
	subscribeExactQos1(
		client,
		configuration.CommandsTopic,
		func(
			client mqtt.Client,
			message mqtt.Message,
		) {
			handleScadalgeriaCommand(
				client,
				message.Payload(),
			)
		},
	)

	authenticated.Store(true)

	fmt.Println(
		"SCADALGERIA session authenticated; telemetry and commands are enabled",
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

func buildEnvelopeAAD(
	sequence uint64,
	timestampMs uint64,
) []byte {
	aad := make([]byte, 16)

	binary.BigEndian.PutUint64(
		aad[0:8],
		sequence,
	)

	binary.BigEndian.PutUint64(
		aad[8:16],
		timestampMs,
	)

	return aad
}

func encryptScadalgeriaPayload(
	innerMessage any,
) []byte {
	sequence := reserveNextSequence()
	timestampMs := currentUnixMilliseconds()

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	must(err)

	plaintext, err := msgpack.Marshal(
		innerMessage,
	)
	must(err)

	blockCipher, err := aes.NewCipher(
		requireSessionKey(),
	)
	must(err)

	aesGcm, err := cipher.NewGCMWithTagSize(
		blockCipher,
		16,
	)
	must(err)

	ciphertextAndTag := aesGcm.Seal(
		nil,
		nonce,
		plaintext,
		buildEnvelopeAAD(
			sequence,
			timestampMs,
		),
	)

	ciphertextLength := len(ciphertextAndTag) - 16

	ciphertext := append(
		[]byte(nil),
		ciphertextAndTag[:ciphertextLength]...,
	)

	gcmTag := append(
		[]byte(nil),
		ciphertextAndTag[ciphertextLength:]...,
	)

	envelope, err := msgpack.Marshal(
		[]any{
			configuration.ApiKeyID,
			nonce,
			ciphertext,
			gcmTag,
			sequence,
			timestampMs,
		},
	)
	must(err)

	return envelope
}

func decryptScadalgeriaPayload(
	envelopePayload []byte,
) []any {
	var envelope []any

	must(
		msgpack.Unmarshal(
			envelopePayload,
			&envelope,
		),
	)

	if len(envelope) != 6 {
		panic("AesGcmEnvelopeDto must contain exactly 6 fields")
	}

	keyID := requireString(
		envelope[0],
		"KeyId",
	)

	nonce := requireBytes(
		envelope[1],
		"Nonce",
	)

	ciphertext := requireBytes(
		envelope[2],
		"Ciphertext",
	)

	gcmTag := requireBytes(
		envelope[3],
		"GcmTag",
	)

	sequence := requireUnsignedInteger(
		envelope[4],
		"Seq",
	)

	timestampMs := requireUnsignedInteger(
		envelope[5],
		"TsUnixMs",
	)

	if keyID != configuration.ApiKeyID {
		panic("Encrypted envelope KeyId does not match this credential")
	}

	if len(nonce) != 12 {
		panic("Encrypted envelope nonce must be 12 bytes")
	}

	if len(gcmTag) != 16 {
		panic("Encrypted envelope GCM tag must be 16 bytes")
	}

	blockCipher, err := aes.NewCipher(
		requireSessionKey(),
	)
	must(err)

	aesGcm, err := cipher.NewGCMWithTagSize(
		blockCipher,
		16,
	)
	must(err)

	ciphertextAndTag := append(
		append(
			[]byte(nil),
			ciphertext...,
		),
		gcmTag...,
	)

	plaintext, err := aesGcm.Open(
		nil,
		nonce,
		ciphertextAndTag,
		buildEnvelopeAAD(
			sequence,
			timestampMs,
		),
	)
	must(err)

	var innerMessage []any

	must(
		msgpack.Unmarshal(
			plaintext,
			&innerMessage,
		),
	)

	return innerMessage
}

func publishEncryptedMessage(
	client mqtt.Client,
	topic string,
	innerMessage any,
) {
	payload := encryptScadalgeriaPayload(
		innerMessage,
	)

	token := client.Publish(
		topic,
		1,
		false,
		payload,
	)

	token.Wait()
	must(token.Error())
}

// ============================================================================
// STEP 7 OF 9 — MQTT HELPERS, AUTHENTICATION, AND TELEMETRY
// ============================================================================

func publishDigitalInputTelemetry(
	client mqtt.Client,
	inputLine *gpiocdev.Line,
) {
	inputValue := readDigitalInput(
		inputLine,
	)

	tagFrame := []any{
		inputTagAddress,
		float64(inputValue),
		nil,
		int64(0),
		192,
	}

	tagFrameBatch := []any{
		[]any{tagFrame},
		nil,
		1,
	}

	publishEncryptedMessage(
		client,
		configuration.TelemetryTopic,
		tagFrameBatch,
	)

	fmt.Printf(
		"Telemetry sent: %s=%d\n",
		inputTagAddress,
		inputValue,
	)
}

// ============================================================================
// STEP 8 OF 9 — COMMAND VALIDATION, LOCAL ACTUATION, AND COMMAND RESULT
// ============================================================================

func parseOutputBit(value any) int {
	switch typed := value.(type) {
	case bool:
		if typed {
			return 1
		}
		return 0

	case int:
		if typed == 0 || typed == 1 {
			return typed
		}
	case int8:
		if typed == 0 || typed == 1 {
			return int(typed)
		}
	case int16:
		if typed == 0 || typed == 1 {
			return int(typed)
		}
	case int32:
		if typed == 0 || typed == 1 {
			return int(typed)
		}
	case int64:
		if typed == 0 || typed == 1 {
			return int(typed)
		}
	case uint8:
		if typed <= 1 {
			return int(typed)
		}
	case uint16:
		if typed <= 1 {
			return int(typed)
		}
	case uint32:
		if typed <= 1 {
			return int(typed)
		}
	case uint64:
		if typed <= 1 {
			return int(typed)
		}
	case float32:
		if typed == 0 || typed == 1 {
			return int(typed)
		}
	case float64:
		if typed == 0 || typed == 1 {
			return int(typed)
		}
	}

	panic("do.output1 accepts only 0 or 1")
}

func handleScadalgeriaCommand(
	client mqtt.Client,
	encryptedPayload []byte,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Println(
				"SCADALGERIA protocol error:",
				recovered,
			)
		}
	}()

	command := decryptScadalgeriaPayload(
		encryptedPayload,
	)

	if len(command) != 10 {
		panic("CommandDto must contain exactly 10 fields")
	}

	commandID := requireString(
		command[0],
		"Command Id",
	)

	if commandID == "" {
		panic("Command Id must not be empty")
	}

	if cachedResult, found := getCachedCommandResult(commandID); found {
		fmt.Printf(
			"Command redelivery detected: %s; returning cached result\n",
			commandID,
		)

		publishEncryptedMessage(
			client,
			configuration.CommandResultTopic,
			cachedResult,
		)

		return
	}

	var finalResult []any

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				finalResult = []any{
					commandID,
					false,
					boundedErrorText(recovered),
					nil,
					1,
				}
			}
		}()

		tagAddress := requireString(
			command[1],
			"TagAddress",
		)

		expiryEpochSeconds := requireUnsignedInteger(
			command[4],
			"Expiry",
		)

		requiresConfirmation := requireBoolean(
			command[7],
			"RequiresConfirmation",
		)

		confirmed := requireBoolean(
			command[8],
			"Confirmed",
		)

		schemaVersion := requireUnsignedInteger(
			command[9],
			"SchemaVersion",
		)

		if schemaVersion != 2 {
			panic("unsupported CommandDto schema version")
		}

		if tagAddress != outputTagAddress {
			panic("unsupported command address: " + tagAddress)
		}

		if int64(expiryEpochSeconds) <= time.Now().Unix() {
			panic("command expired")
		}

		if requiresConfirmation && !confirmed {
			panic("command requires operator confirmation")
		}

		outputValue := parseOutputBit(
			command[2],
		)

		must(
			writeDigitalOutput(
				outputLine,
				outputValue,
			),
		)

		resultData, err := json.Marshal(
			map[string]int{
				"appliedValue": outputValue,
			},
		)
		must(err)

		finalResult = []any{
			commandID,
			true,
			nil,
			string(resultData),
			1,
		}

		fmt.Printf(
			"Command applied: %s=%d\n",
			outputTagAddress,
			outputValue,
		)
	}()

	rememberCommandResult(
		commandID,
		finalResult,
	)

	publishEncryptedMessage(
		client,
		configuration.CommandResultTopic,
		finalResult,
	)
}

// ============================================================================
// STEP 9 OF 9 — MQTT 3.1.1 LIFECYCLE, RECONNECT, AND MAIN LOOP
//
// Paho is pinned to MQTT 3.1.1 with CleanSession=true. Auto-reconnect is
// allowed, but OnConnect always clears the previous AES session and starts
// from the exact authChallenge topic again.
// ============================================================================

func main() {
	inputLine, localOutputLine := initializeDigitalIO()

	defer inputLine.Close()
	defer localOutputLine.Close()

	outputLine = localOutputLine

	brokerUri := fmt.Sprintf(
		"tcp://%s:%d",
		configuration.Host,
		configuration.Port,
	)

	options := mqtt.NewClientOptions()

	options.AddBroker(brokerUri)
	options.SetClientID(configuration.ClientID)
	options.SetUsername(configuration.MqttUsername)

	// The Direct Firmware API token is not the MQTT password.
	options.SetPassword("")

	options.SetCleanSession(true)
	options.SetProtocolVersion(4) // MQTT 3.1.1

	options.SetAutoReconnect(true)
	options.SetConnectRetry(true)
	options.SetConnectRetryInterval(5 * time.Second)
	options.SetMaxReconnectInterval(30 * time.Second)

	options.SetOnConnectHandler(
		func(client mqtt.Client) {
			clearAuthenticatedSession()

			fmt.Println(
				"MQTT connected; waiting for a fresh SCADALGERIA challenge",
			)

			defer func() {
				if recovered := recover(); recovered != nil {
					clearAuthenticatedSession()
					fmt.Println(
						"Unable to subscribe to authentication challenge:",
						recovered,
					)
				}
			}()

			subscribeExactQos1(
				client,
				configuration.AuthChallengeTopic,
				func(
					client mqtt.Client,
					message mqtt.Message,
				) {
					defer func() {
						if recovered := recover(); recovered != nil {
							clearAuthenticatedSession()

							fmt.Println(
								"Authentication failed:",
								recovered,
							)
						}
					}()

					authenticateWithScadalgeria(
						client,
						message.Payload(),
					)
				},
			)
		},
	)

	options.SetConnectionLostHandler(
		func(
			_ mqtt.Client,
			reason error,
		) {
			clearAuthenticatedSession()

			fmt.Println(
				"MQTT connection lost; next connection must re-authenticate:",
				reason,
			)
		},
	)

	client := mqtt.NewClient(options)

	connectToken := client.Connect()
	connectToken.Wait()
	must(connectToken.Error())

	authenticationDeadline := time.After(
		20 * time.Second,
	)

	for !authenticated.Load() {
		select {
		case <-authenticationDeadline:
			panic("SCADALGERIA authentication timed out")
		default:
			time.Sleep(25 * time.Millisecond)
		}
	}

	telemetryTicker := time.NewTicker(
		time.Second,
	)
	defer telemetryTicker.Stop()

	for range telemetryTicker.C {
		if !authenticated.Load() {
			continue
		}

		publishDigitalInputTelemetry(
			client,
			inputLine,
		)

		// Also obey the copied configuration telemetryPolicy. The one-second interval
		// is only the public example cadence.
	}
}

// ============================================================================
// SMALL TYPE-SAFE DECODING HELPERS
//
// vmihailenco/msgpack decodes positional arrays into `any` values here, so the
// device validates types explicitly before using untrusted broker payloads.
// ============================================================================

func requireString(value any, fieldName string) string {
	typed, ok := value.(string)

	if !ok {
		panic(fieldName + " must be a string")
	}

	return typed
}

func requireBytes(value any, fieldName string) []byte {
	typed, ok := value.([]byte)

	if !ok {
		panic(fieldName + " must be MessagePack binary")
	}

	return typed
}

func requireBoolean(value any, fieldName string) bool {
	typed, ok := value.(bool)

	if !ok {
		panic(fieldName + " must be a boolean")
	}

	return typed
}

func requireUnsignedInteger(value any, fieldName string) uint64 {
	switch typed := value.(type) {
	case uint64:
		return typed
	case uint:
		return uint64(typed)
	case uint32:
		return uint64(typed)
	case uint16:
		return uint64(typed)
	case uint8:
		return uint64(typed)
	case int:
		if typed >= 0 {
			return uint64(typed)
		}
	case int64:
		if typed >= 0 {
			return uint64(typed)
		}
	case int32:
		if typed >= 0 {
			return uint64(typed)
		}
	}

	panic(fieldName + " must be a non-negative integer")
}

func boundedErrorText(value any) string {
	runes := []rune(
		fmt.Sprint(value),
	)

	if len(runes) > 256 {
		runes = runes[:256]
	}

	return string(runes)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
