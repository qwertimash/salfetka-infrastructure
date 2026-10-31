package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/jobs"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
	"salfetka/panel/internal/subscriptionsets"
)

func run() error {
	dsn, e := appconfig.DatabaseURL()
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, e := pgxpool.New(startup, dsn)
	if e != nil {
		return errors.New("database_configuration_failed")
	}
	defer pool.Close()
	if e = database.Ready(startup, pool); e != nil {
		return errors.New("database_not_ready_run_migrations")
	}
	vault, e := appconfig.LoadVault()
	if e != nil {
		return e
	}
	if e = secrets.BindInstallation(startup, pool, vault); e != nil {
		return errors.New("installation_key_check_failed")
	}
	sets := subscriptionsets.Store{Builder: builder.New(pool, vault)}
	releaseStore := releases.New(pool, vault, nodes.New(pool, vault, nil))
	publicationTick := time.NewTimer(0)
	defer publicationTick.Stop()
	catalogStore := catalog.New(pool, vault)
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		ticker := time.NewTimer(0)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				work, cancel := context.WithTimeout(ctx, 15*time.Second)
				_, err := catalogStore.RefreshOne(work)
				cancel()
				if err != nil && ctx.Err() == nil {
					slog.Warn("source_refresh_iteration_failed", "code", "source_refresh_failed")
				}
				ticker.Reset(5 * time.Second)
			}
		}
	}()
	defer func() { stop(); <-refreshDone }()
	b := make([]byte, 16)
	if _, e = rand.Read(b); e != nil {
		return errors.New("random_source_failed")
	}
	workerID := "worker_" + hex.EncodeToString(b)
	store := jobs.New(pool)
	accessStore := access.New(pool, nil)
	expiryTick := time.NewTimer(0)
	defer expiryTick.Stop()
	slog.Info("panel_worker_started")
	delay := time.NewTimer(0)
	defer delay.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-publicationTick.C:
			work, done := context.WithTimeout(ctx, 15*time.Second)
			_, err := sets.ScanTargets(work)
			worked := false
			if err == nil {
				worked, err = sets.RunOne(work, releaseStore)
			}
			done()
			if err != nil && ctx.Err() == nil {
				slog.Warn("publication_iteration_failed", "code", "publication_failed")
			}
			interval := time.Second
			if worked && err == nil {
				interval = 50 * time.Millisecond
			}
			publicationTick.Reset(interval)
		case <-expiryTick.C:
			work, done := context.WithTimeout(ctx, 15*time.Second)
			count, err := accessStore.ReconcileExpired(work, 100)
			done()
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				slog.Warn("access_expiry_iteration_failed", "code", "access_expiry_failed")
			}
			if count == 100 && err == nil {
				expiryTick.Reset(100 * time.Millisecond)
			} else {
				expiryTick.Reset(10 * time.Second)
			}
		case <-delay.C:
			work, done := context.WithTimeout(ctx, 15*time.Second)
			_, e = store.RunOne(work, workerID)
			done()
			if ctx.Err() != nil {
				return nil
			}
			if e != nil {
				slog.Warn("job_iteration_failed", "code", "job_processing_failed")
				delay.Reset(3 * time.Second)
			} else {
				delay.Reset(500 * time.Millisecond)
			}
		}
	}
}
func main() {
	if e := run(); e != nil {
		slog.Error("panel_worker_failed", "code", e.Error())
		os.Exit(1)
	}
}
