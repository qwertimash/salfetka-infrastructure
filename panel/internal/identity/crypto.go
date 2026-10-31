package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const passwordMemory = 64 * 1024
const passwordIterations = 3

// Tokens have 256 bits of entropy; only their hashes are persisted.
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func TokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CSRF is stable across tabs/reloads and cannot be used as the session bearer.
// The domain separation also prevents it being confused with a stored token hash.
func CSRFToken(sessionToken string) string {
	h := sha256.Sum256([]byte("salfetka-csrf-v1:" + sessionToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func tokenValid(token string) bool {
	b, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(b) == 32 && len(token) == 43
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", ErrUnavailable
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func hashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 128 {
		return "", ErrInvalid
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", ErrUnavailable
	}
	key := argon2.IDKey([]byte(password), salt, passwordIterations, passwordMemory, 1, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", passwordMemory, passwordIterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func verifyPassword(password, encoded string) bool {
	if len(password) > 128 || len(encoded) > 512 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false
	}
	values := make([]uint32, 3)
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(params[i], prefix) {
			return false
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(params[i], prefix), 10, 32)
		if err != nil {
			return false
		}
		values[i] = uint32(n)
	}
	// Corrupt or attacker-controlled DB data must not request unbounded work.
	if values[0] < 19456 || values[0] > passwordMemory || values[1] < 1 || values[1] > 4 || values[2] < 1 || values[2] > 4 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, values[1], values[0], uint8(values[2]), 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func dummyPasswordCheck(password string) {
	_ = argon2.IDKey([]byte(password), []byte("salfetka-dummy-v1"), passwordIterations, passwordMemory, 1, 32)
}
