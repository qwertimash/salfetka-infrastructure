package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/nodes"
)

// The CA is a separate private bundle. This command creates it once; it never
// silently rotates an existing issuer or repairs a partially written bundle.
func initNodeAuthority(args []string) error {
	flags := flag.NewFlagSet("init-node-authority", flag.ContinueOnError)
	path := flags.String("file", "", "private node authority bundle")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" {
		return errors.New("node_authority_file_required")
	}
	dir := filepath.Dir(*path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("node_authority_directory_not_private")
	}
	if _, err := os.Lstat(*path); err == nil {
		data, err := appconfig.PrivateFile(*path)
		if err != nil {
			return errors.New("node_authority_invalid")
		}
		if _, err = nodes.LoadAuthority(data); err != nil {
			return errors.New("node_authority_invalid")
		}
		fmt.Println("existing_node_authority_preserved")
		return nil
	} else if !os.IsNotExist(err) {
		return errors.New("node_authority_unreadable")
	}
	data, err := nodes.GenerateAuthority()
	if err != nil {
		return errors.New("node_authority_generation_failed")
	}
	f, err := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("node_authority_create_failed")
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("node_authority_write_failed")
	}
	parent, err := os.Open(dir)
	if err != nil {
		return errors.New("node_authority_directory_sync_failed")
	}
	err = parent.Sync()
	closeErr = parent.Close()
	if err != nil || closeErr != nil {
		return errors.New("node_authority_directory_sync_failed")
	}
	fmt.Println("node_authority_created_private_file")
	return nil
}
