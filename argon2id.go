package apikeys

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	nanoid "github.com/matoous/go-nanoid"
	"golang.org/x/crypto/argon2"
)

const (
	StandardAlg   = "argon2id 3 64MB 32"
	saltLen       = 32
	passwordLen   = 32
	apiKeyNameLen = 16
	argon2Threads = 1

	// 21 gives us similar properties to uuid.
	defaultClientNanoIDLen = 21

	apiKeySecretParts  = 3
	apiKeyAlgPart      = 0 // alg.salt.password encoded together
	apiKeySaltPart     = 1
	apiKeyPasswordPart = 2
)

type Key struct {
	alg Alg `firestore:"-" json:"-" protobuf:"-" mapstructure:"-"`
	// Salt is randomly generated when the password is generated. It is safe to (and must be) return to the api key holder
	Salt []byte `firestore:"-" json:"-" protobuf:"-" mapstructure:"-"`
	// DerivedKey is derived from a randomly generated password. The key is
	// persistently stored. In the api key usage model this key is NOT
	// sensitive. But also is NOT returned to the user - instead, we return the
	// password and salt to the user. The password is NOT stored in this type
	// ever.
	DerivedKey []byte `firestore:"derived_key" json:"derived_key" protobuf:"derived_key" mapstructure:"derived_key"`

	ClientID string `firestore:"client_id" json:"client_id" protobuf:"client_id" mapstructure:"client_id"`
}

func (ak Key) Alg() Alg {
	return ak.alg
}

type KeyOption func(*Key)

func WithClientID(clientID string) KeyOption {
	return func(ak *Key) {
		ak.ClientID = clientID
	}
}

func NewKey(alg string, opts ...KeyOption) (Key, error) {

	ak := Key{}
	err := ak.SetOptions(alg, opts...)
	return ak, err
}

func (ak *Key) SetOptions(alg string, opts ...KeyOption) error {
	var err error

	ak.alg, err = ParseAlg(alg)
	if err != nil {
		return err
	}

	for _, o := range opts {
		o(ak)
	}

	// If we didn't get an explicit client id, make one up
	if len(ak.ClientID) == 0 {
		ak.ClientID, err = nanoid.ID(defaultClientNanoIDLen)
		if err != nil {
			return nil
		}
	}
	return nil
}

func Decode(apikey string) (Key, []byte, error) {

	b, err := base64.URLEncoding.DecodeString(apikey)
	if err != nil {
		return Key{}, nil, err
	}

	parts := strings.SplitN(string(b), ":", 3)
	if len(parts) > 2 {
		return Key{}, nil, fmt.Errorf("outer structure invalid want a single ':' separating client id from secret")
	}

	ak := Key{ClientID: parts[0]}

	parts = strings.SplitN(string(parts[1]), ".", apiKeySecretParts+1)

	if len(parts) != apiKeySecretParts {
		return Key{}, nil, fmt.Errorf(
			"invalid number of '.' seperated secret parts in api key. got %d, wanted %d", len(parts), apiKeySecretParts)
	}

	ak.alg, err = ParseAlg(parts[apiKeyAlgPart])
	if err != nil {
		return Key{}, nil, err
	}

	ak.Salt, err = base64.URLEncoding.DecodeString(parts[apiKeySaltPart])
	if err != nil {
		return Key{}, nil, err
	}
	password, err := base64.URLEncoding.DecodeString(parts[apiKeyPasswordPart])
	if err != nil {
		return Key{}, nil, err
	}

	return ak, password, nil
}

func (ak *Key) RecoverKey(password []byte) []byte {

	return argon2.IDKey(password, ak.Salt, ak.alg.Time, ak.alg.Memory, argon2Threads, ak.alg.KeyLen)
}

func (ak *Key) MatchPassword(password, key []byte) bool {

	ak.DerivedKey = ak.RecoverKey(password)

	return bytes.Equal(ak.DerivedKey, key)
}

// EncodedKey returns the derived key in url safe base64 encoded form.
func (ak *Key) EncodedKey() string {
	return base64.URLEncoding.EncodeToString(ak.DerivedKey)
}

func (ak *Key) generatePasword() ([]byte, error) {

	ak.Salt = make([]byte, saltLen)
	n, err := rand.Read(ak.Salt)
	if err != nil {
		return nil, err
	}
	if n != saltLen {
		return nil, fmt.Errorf("insufficient rand bytes generating salt")
	}

	password := make([]byte, passwordLen)
	n, err = rand.Read(password)
	if err != nil {
		return nil, err
	}
	if n != passwordLen {
		return nil, fmt.Errorf("insufficient rand bytes generating password")
	}

	ak.DerivedKey = argon2.IDKey(password, ak.Salt, ak.alg.Time, ak.alg.Memory, argon2Threads, ak.alg.KeyLen)

	return password, nil
}

// Generate creates a new random password and salt and encodes it for delivery
// with the following format
// 	base64(clientid:alg.base64(salt).base64(secret))
// The format is chosen to be compatible with client_credentials flow where the
// client_id:secret are delivered together in a in an "Authorization: Basic
// base64(id:secret)" header. The token endpoint needs to be aware of what to do
// with the secret part in order for that to work.
func (ak *Key) Generate() (string, error) {
	password, err := ak.generatePasword()
	if err != nil {
		return "", err
	}
	salt := base64.URLEncoding.EncodeToString(ak.Salt)
	secret := base64.URLEncoding.EncodeToString(password)

	secret = strings.Join([]string{ak.alg.String, salt, secret}, ".")
	secret = strings.Join([]string{ak.ClientID, secret}, ":")
	return base64.URLEncoding.EncodeToString([]byte(secret)), nil
}
