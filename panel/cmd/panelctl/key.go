package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"salfetka/panel/internal/appconfig"
)

// init-key only creates a missing installation key. Retrying never rotates it.
func initKey(args []string) error {
	flags := flag.NewFlagSet("init-key", flag.ContinueOnError)
	path := flags.String("file", "", "private installation master key file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" {
		return errors.New("key_file_required")
	}
	if _, err := os.Lstat(*path); err == nil {
		b, e := appconfig.PrivateFile(*path)
		if e != nil {
			return errors.New("master_key_invalid")
		}
		key, e := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
		if e != nil || len(key) != 32 {
			return errors.New("master_key_invalid")
		}
		fmt.Println("existing_master_key_preserved")
		return nil
	} else if !os.IsNotExist(err) {
		return errors.New("master_key_unreadable")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return errors.New("random_source_failed")
	}
	f, err := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("master_key_create_failed")
	}
	_, err = f.WriteString(base64.RawURLEncoding.EncodeToString(key) + "\n")
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("master_key_write_failed")
	}
	fmt.Println("master_key_created_private_file")
	return nil
}
