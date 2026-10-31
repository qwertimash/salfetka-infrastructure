package secrets

import (
	"bytes"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
)

const bindingContext = "installation-key-check"
const bindingValue = "salfetka-installation-key-v1"

// BindInstallation initializes an encrypted known value once, then verifies it
// at startup. A missing or wrong key cannot silently create mixed-key data.
// Runtime roles need only SELECT and INSERT on access_key_state.
func BindInstallation(ctx context.Context, pool *pgxpool.Pool, v *Vault) error {
	if pool == nil || v == nil {
		return ErrUnavailable
	}
	encrypted, err := v.Seal([]byte(bindingValue), bindingContext)
	if err != nil {
		return ErrUnavailable
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer database.Rollback(tx)
	if _, err = tx.Exec(ctx, "INSERT INTO access_key_state(singleton,encrypted_check) VALUES(true,$1) ON CONFLICT(singleton) DO NOTHING", encrypted); err != nil {
		return ErrUnavailable
	}
	var existing []byte
	if err = tx.QueryRow(ctx, "SELECT encrypted_check FROM access_key_state WHERE singleton").Scan(&existing); err != nil {
		return ErrUnavailable
	}
	plain, err := v.Open(existing, bindingContext)
	if err != nil || !bytes.Equal(plain, []byte(bindingValue)) {
		return ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}
