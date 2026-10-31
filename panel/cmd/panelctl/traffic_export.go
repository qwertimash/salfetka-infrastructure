package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/trafficexport"
)

func exportTraffic(args []string) error {
	flags := flag.NewFlagSet("export-traffic", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nodesFile := flags.String("nodes-file", "", "private JSON array of explicit node UUIDs")
	output := flags.String("output-dir", "", "existing private directory for snapshot.json")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *nodesFile == "" || *output == "" {
		return trafficexport.ErrInvalid
	}
	raw, err := appconfig.PrivateFile(*nodesFile)
	if err != nil {
		return trafficexport.ErrInvalid
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil || !trafficexport.ValidNodes(ids) {
		return trafficexport.ErrInvalid
	}
	// Lock before opening DB/read, not just before rename.
	writer, err := trafficexport.Open(*output)
	if err != nil {
		return err
	}
	defer writer.Close()
	dsn, err := appconfig.DatabaseURL()
	if err != nil {
		return trafficexport.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return trafficexport.ErrUnavailable
	}
	defer pool.Close()
	raw, err = trafficexport.Read(ctx, pool, ids)
	if err != nil {
		return err
	}
	if err = writer.Write(raw); err != nil {
		return err
	}
	fmt.Println("traffic_snapshot_exported_observation_only")
	return nil
}
