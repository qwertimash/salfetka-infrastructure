// Package bypasslease is the durable account session coordinator.
// Production use requires the authenticated machine boundary and verified
// device proof from the account-capable engine; the feature is opt-in.
package bypasslease

import (
	"errors"
	"regexp"
	"time"

	"salfetka/panel/internal/database"
)

const (
	LeaseTTL    = 30 * time.Second
	PrepareTTL  = time.Minute
	MaxSequence = int64(9007199254740991)
	Replaced    = "session_replaced"
)

var (
	ErrInvalid  = errors.New("bypass_lease_invalid")
	ErrDenied   = errors.New("bypass_lease_denied")
	ErrConflict = errors.New("bypass_lease_conflict")
	ErrStale    = errors.New("bypass_lease_stale")
	ErrPending  = errors.New("bypass_lease_waiting_for_close")
	ErrExpired  = errors.New("bypass_lease_expired")
	ErrClock    = errors.New("bypass_lease_clock_untrusted")
)

// Owner is established by authenticated node identity plus verified device proof,
// never by copying an arbitrary HTTP body. User/device are resolved from the DB.
type Owner struct {
	NodeID         string
	InstallationID string
	EngineEpoch    string
	CredentialID   string
}
type Ref struct {
	UserID     string
	Generation int64
}
type Lease struct {
	Ref
	Owner
	DeviceID  string
	RequestID string
	State     string
	Reason    string
	Revision  int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

var epochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (o Owner) valid() bool {
	return database.ValidID(o.NodeID) && database.ValidID(o.InstallationID) && database.ValidID(o.CredentialID) && epochPattern.MatchString(o.EngineEpoch)
}
func (r Ref) valid() bool {
	return database.ValidID(r.UserID) && r.Generation > 0 && r.Generation <= MaxSequence
}
