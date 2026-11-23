package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"

	"morse/backend/internal/jcs"
)

const (
	configIDKeyProvider   = 0x02
	configIDDocument      = 0x03
	configIDDigestEnd     = 1 + sha256.Size
	mrConfigV3Version     = 3
	mrConfigV3Domain      = "dstack-mr-config-v3:\x00"
	manifestInitScriptsV3 = 3
)

// why: dstack-types mr_config.rs key_provider_kind_byte, and the KeyProviderKind serde names in lib.rs.
var keyProviderKindByte = map[string]byte{"none": 0, "local": 1, "kms": 2, "tpm": 3, "sev-snp": 4}

type configBinding struct {
	composeHash   [sha256.Size]byte
	appID         []byte
	instanceID    []byte
	gpuPolicyHash []byte
	appCompose    string
}

func checkConfigID(mrConfigID []byte, b configBinding) error {
	if len(mrConfigID) != configIDLen || !bytes.Equal(mrConfigID[configIDDigestEnd:], make([]byte, configIDLen-configIDDigestEnd)) {
		return fmt.Errorf("%w: mrconfigid %x is not a version byte, a 32-byte digest and zeros", ErrConfigID, mrConfigID)
	}
	var want []byte
	switch version := mrConfigID[0]; version {
	case configIDComposeHash:
		want = b.composeHash[:]
	// why: dstack 08e4440a dstack-types/src/mr_config.rs MrConfig::V2 and vmm/src/app/mr_config.rs: keccak256(compose_hash || app_id || kind byte || the compose's key_provider_id bytes).
	case configIDKeyProvider:
		kind, id, err := composeKeyProvider(b.appCompose)
		if err != nil {
			return fmt.Errorf("%w: %w: mrconfigid version 2: %w", ErrConfigID, ErrUnreadable, err)
		}
		h := sha3.NewLegacyKeccak256()
		for _, part := range [][]byte{b.composeHash[:], b.appID, {keyProviderKindByte[kind]}, id} {
			h.Write(part)
		}
		want = h.Sum(nil)
	case configIDDocument:
		document, err := mrConfigV3Document(b)
		if err != nil {
			return fmt.Errorf("%w: %w: mrconfigid version 3: %w", ErrConfigID, ErrUnreadable, err)
		}
		sum := sha256.Sum256([]byte(mrConfigV3Domain + string(document)))
		if !bytes.Equal(mrConfigID[1:configIDDigestEnd], sum[:]) {
			return fmt.Errorf("%w: %w: mrconfigid %x is not the version 3 document the measured values rebuild, %s", ErrConfigID, ErrUnreadable, mrConfigID, document)
		}
		return nil
	case 0:
		return fmt.Errorf("%w: mrconfigid %x binds no config", ErrConfigID, mrConfigID)
	default:
		return fmt.Errorf("%w: %w: mrconfigid version %d", ErrConfigID, ErrUnreadable, version)
	}
	if !bytes.Equal(mrConfigID[1:configIDDigestEnd], want) {
		return fmt.Errorf("%w: mrconfigid %x, want version %d digest %x", ErrConfigID, mrConfigID, mrConfigID[0], want)
	}
	return nil
}

type mrConfigV3 struct {
	AppID            string    `json:"app_id,omitempty"`
	ComposeHash      string    `json:"compose_hash"`
	GPUPolicyHash    *string   `json:"gpu_policy_hash,omitempty"`
	InitScriptHashes *[]string `json:"init_script_hashes,omitempty"`
	InstanceID       string    `json:"instance_id,omitempty"`
	KeyProvider      string    `json:"key_provider"`
	KeyProviderID    string    `json:"key_provider_id,omitempty"`
	Version          int       `json:"version"`
}

// why: dstack's VMM builds the document in vmm/src/app/mr_config.rs prepare_mr_config_v3: the key provider from
// the compose, app and instance ids as the guest measures them, the GPU policy hash for a GPU launch, and the
// init script hashes from manifest version 3.
func mrConfigV3Document(b configBinding) ([]byte, error) {
	kind, id, err := composeKeyProvider(b.appCompose)
	if err != nil {
		return nil, err
	}
	doc := mrConfigV3{
		AppID:         hex.EncodeToString(b.appID),
		ComposeHash:   hex.EncodeToString(b.composeHash[:]),
		InstanceID:    hex.EncodeToString(b.instanceID),
		KeyProvider:   kind,
		KeyProviderID: hex.EncodeToString(id),
		Version:       mrConfigV3Version,
	}
	if b.gpuPolicyHash != nil {
		h := hex.EncodeToString(b.gpuPolicyHash)
		doc.GPUPolicyHash = &h
	}
	fields, err := manifestFields(b.appCompose)
	if err != nil {
		return nil, fmt.Errorf("app_compose: %w", err)
	}
	if manifestVersion(fields["manifest_version"]) >= manifestInitScriptsV3 {
		scripts, err := initScripts(fields["init_script"])
		if err != nil {
			return nil, err
		}
		hashes := make([]string, len(scripts))
		for i, s := range scripts {
			sum := sha256.Sum256([]byte(s))
			hashes[i] = hex.EncodeToString(sum[:])
		}
		doc.InitScriptHashes = &hashes
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return jcs.Canonicalize(raw)
}

// why: dstack-types AppCompose::key_provider names key_provider when it is set, else kms for kms_enabled, else
// local for local_key_provider_enabled, else none.
func composeKeyProvider(appCompose string) (string, []byte, error) {
	var c struct {
		KeyProvider      *string `json:"key_provider"`
		KeyProviderID    string  `json:"key_provider_id"`
		KMSEnabled       bool    `json:"kms_enabled"`
		LocalKeyProvider bool    `json:"local_key_provider_enabled"`
	}
	if _, err := manifestFields(appCompose); err != nil {
		return "", nil, fmt.Errorf("app_compose: %w", err)
	}
	if err := json.Unmarshal([]byte(appCompose), &c); err != nil {
		return "", nil, fmt.Errorf("app_compose key provider: %w", err)
	}
	kind := "none"
	switch {
	case c.KeyProvider != nil:
		kind = *c.KeyProvider
	case c.KMSEnabled:
		kind = "kms"
	case c.LocalKeyProvider:
		kind = "local"
	}
	if _, ok := keyProviderKindByte[kind]; !ok {
		return "", nil, fmt.Errorf("app_compose key_provider %q", kind)
	}
	id, err := hex.DecodeString(strings.TrimPrefix(c.KeyProviderID, "0x"))
	if err != nil {
		return "", nil, fmt.Errorf("app_compose key_provider_id %q is not hex", c.KeyProviderID)
	}
	return kind, id, nil
}

func manifestVersion(raw json.RawMessage) uint64 {
	var text string
	if json.Unmarshal(raw, &text) != nil {
		text = string(raw)
	}
	v, _ := strconv.ParseUint(text, 10, 32)
	return v
}

func initScripts(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("app_compose init_script: %w", err)
	}
	return many, nil
}
