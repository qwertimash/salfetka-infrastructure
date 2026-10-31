package identity

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("invalid_request")
	ErrCredentials  = errors.New("invalid_credentials")
	ErrUnauthorized = errors.New("unauthenticated")
	ErrForbidden    = errors.New("forbidden")
	ErrCSRF         = errors.New("csrf_failed")
	ErrRateLimited  = errors.New("rate_limited")
	ErrSetup        = errors.New("setup_unavailable")
	ErrConflict     = errors.New("conflict")
	ErrRevision     = errors.New("revision_conflict")
	ErrLastOwner    = errors.New("last_owner")
	ErrNotFound     = errors.New("not_found")
	ErrUnavailable  = errors.New("unavailable")
)

type Role string

const (
	Owner                  Role = "owner"
	AccessOperator         Role = "access_operator"
	InfrastructureOperator Role = "infrastructure_operator"
	Support                Role = "support"
	Auditor                Role = "auditor"
)

func (r Role) Valid() bool {
	return r == Owner || r == AccessOperator || r == InfrastructureOperator || r == Support || r == Auditor
}

type Admin struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	Disabled  bool      `json:"disabled"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Session struct {
	User      Admin     `json:"user"`
	CSRFToken string    `json:"csrf_token"`
	Token     string    `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,63}$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func NormalizeUsername(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !usernamePattern.MatchString(s) {
		return "", ErrInvalid
	}
	return s, nil
}

func ValidID(s string) bool { return idPattern.MatchString(s) }
