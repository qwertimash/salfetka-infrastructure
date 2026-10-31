package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
)

type bootstrapFile struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func tokenFile(path string) (bootstrapFile, error) {
	var value bootstrapFile
	data, e := appconfig.PrivateFile(path)
	if e == nil {
		if json.Unmarshal(data, &value) != nil || value.Token == "" || value.ExpiresAt.IsZero() {
			return value, errors.New("bootstrap_file_invalid")
		}
		return value, nil
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		return value, errors.New("bootstrap_file_unreadable")
	}
	value.Token, e = identity.RandomToken()
	if e != nil {
		return value, errors.New("random_source_failed")
	}
	value.ExpiresAt = time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	data, e = json.Marshal(value)
	if e != nil {
		return value, errors.New("bootstrap_file_failed")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return value, errors.New("bootstrap_file_create_failed")
	}
	if _, e = f.Write(append(data, '\n')); e != nil {
		f.Close()
		return value, errors.New("bootstrap_file_write_failed")
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return value, errors.New("bootstrap_file_sync_failed")
	}
	if e = f.Close(); e != nil {
		return value, errors.New("bootstrap_file_close_failed")
	}
	return value, nil
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("usage_panelctl_migrate_or_bootstrap")
	}
	command := args[0]
	if command == "export-traffic" {
		return exportTraffic(args[1:])
	}
	if command == "prepare" {
		return prepare(args[1:])
	}
	if command == "init-key" {
		return initKey(args[1:])
	}
	if command == "init-node-authority" {
		return initNodeAuthority(args[1:])
	}
	if command == "init-node-signer" {
		return initNodeSigner(args[1:])
	}
	if command != "migrate" && command != "bootstrap" && command != "provision-runtime" {
		return errors.New("unknown_command")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	file := flags.String("token-file", "", "private bootstrap JSON file (token is never printed)")
	passwordFile := flags.String("password-file", "", "private runtime role password file")
	if e := flags.Parse(args[1:]); e != nil || flags.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	if command == "bootstrap" && *file == "" {
		return errors.New("token_file_required")
	}
	dsn, e := appconfig.DatabaseURL()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return errors.New("database_configuration_failed")
	}
	defer pool.Close()
	if command == "migrate" {
		if e = database.Migrate(ctx, pool); e != nil {
			return errors.New("migration_failed")
		}
		fmt.Println("migrations_applied")
		return nil
	}
	if e = database.Ready(ctx, pool); e != nil {
		return errors.New("database_not_ready_run_migrations")
	}
	if command == "provision-runtime" {
		if e = provisionRuntime(ctx, pool, *passwordFile); e != nil {
			return e
		}
		fmt.Println("runtime_role_provisioned")
		return nil
	}
	value, e := tokenFile(*file)
	if e != nil {
		return e
	}
	if !value.ExpiresAt.After(time.Now()) {
		return errors.New("bootstrap_file_expired_prepare_new_file")
	}
	if e = identity.PrepareBootstrap(ctx, pool, identity.TokenHash(value.Token), value.ExpiresAt); e != nil {
		return errors.New("bootstrap_prepare_rejected_or_unavailable")
	}
	fmt.Println("bootstrap_prepared_private_file")
	return nil
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
