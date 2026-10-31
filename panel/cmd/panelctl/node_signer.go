package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/nodecontrol"
)

// A missing public export may be recovered from an existing private signer.
// Existing keys are never replaced, including after a partially completed init.
func initNodeSigner(args []string) error {
	flags := flag.NewFlagSet("init-node-signer", flag.ContinueOnError)
	private := flags.String("file", "", "private command signing key")
	public := flags.String("public-file", "", "public verification key export")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *private == "" || *public == "" || filepath.Clean(*private) == filepath.Clean(*public) {
		return errors.New("node_signer_paths_required")
	}
	for _, path := range []string{*private, *public} {
		info, err := os.Lstat(filepath.Dir(path))
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return errors.New("node_signer_directory_not_private")
		}
	}
	var raw []byte
	if _, err := os.Lstat(*private); err == nil {
		raw, err = appconfig.PrivateFile(*private)
		if err != nil {
			return errors.New("node_signer_invalid")
		}
	} else if os.IsNotExist(err) {
		if _, err := os.Lstat(*public); !os.IsNotExist(err) {
			return errors.New("node_signer_private_missing_public_exists")
		}
		raw, err = nodecontrol.GenerateSigner()
		if err != nil {
			return errors.New("node_signer_generation_failed")
		}
		if err = createSignerFile(*private, raw); err != nil {
			return err
		}
	} else {
		return errors.New("node_signer_unreadable")
	}
	signer, err := nodecontrol.LoadSigner(raw)
	if err != nil {
		return errors.New("node_signer_invalid")
	}
	if _, err := os.Lstat(*public); err == nil {
		existing, err := appconfig.PrivateFile(*public)
		if err != nil || !bytes.Equal(existing, signer.PublicPEM()) {
			return errors.New("node_signer_public_mismatch")
		}
	} else if os.IsNotExist(err) {
		if err := createSignerFile(*public, signer.PublicPEM()); err != nil {
			return err
		}
	} else {
		return errors.New("node_signer_public_unreadable")
	}
	fmt.Println("node_signer_ready_existing_identity_preserved")
	return nil
}

func createSignerFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("node_signer_create_failed")
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("node_signer_write_failed")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("node_signer_directory_sync_failed")
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil || closeErr != nil {
		return errors.New("node_signer_directory_sync_failed")
	}
	return nil
}
