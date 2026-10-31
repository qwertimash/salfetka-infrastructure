package nodevpn

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maxPrivateBytes = 128 * 1024

func fault(code string) error { return errors.New(code) }
func readFD(fd int, private bool) ([]byte, error) {
	f := os.NewFile(uintptr(fd), "vpn_private_file")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 1 || st.Size > maxPrivateBytes || st.Nlink != 1 {
		return nil, fault("vpn_file_invalid")
	}
	if private && (st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid())) {
		return nil, fault("vpn_file_not_private")
	}
	if !private && st.Mode&0022 != 0 {
		return nil, fault("vpn_ca_file_writable")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPrivateBytes+1))
	if err != nil || len(b) > maxPrivateBytes {
		return nil, fault("vpn_file_read_failed")
	}
	return b, nil
}
func readExternal(path string, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fault("vpn_file_unreadable")
	}
	return readFD(fd, private)
}
func openStateDir(path string) (int, int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, -1, fault("vpn_state_directory_invalid")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return -1, -1, fault("vpn_state_directory_unavailable")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, -1, fault("vpn_state_directory_invalid")
	}
	fail := func(code string) (int, int, error) { unix.Close(fd); return -1, -1, fault(code) }
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		return fail("vpn_state_directory_not_private")
	}
	lock, err := unix.Openat(fd, "engine.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fail("vpn_state_lock_failed")
	}
	if unix.Fstat(lock, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		unix.Close(lock)
		return fail("vpn_state_lock_invalid")
	}
	if unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(lock)
		return fail("vpn_state_busy")
	}
	return fd, lock, nil
}
func readState(fd int) ([]byte, error) {
	file, err := unix.Openat(fd, "state.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fault("vpn_state_unreadable")
	}
	return readFD(file, true)
}
func writeState(fd int, state localState) error { return writeStateValue(fd, state) }
func writeStateValue(fd int, state any) error {
	// Refuse unsafe existing targets instead of replacing a symlink/hardlink.
	if _, err := readState(fd); err != nil {
		return err
	}
	bytes, err := json.Marshal(state)
	if err != nil || len(bytes) > maxPrivateBytes {
		return fault("vpn_state_encode_failed")
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return fault("vpn_random_failed")
	}
	temporary := ".state-" + hex.EncodeToString(nonce) + ".tmp"
	file, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fault("vpn_state_write_failed")
	}
	defer unix.Unlinkat(fd, temporary, 0)
	out := os.NewFile(uintptr(file), "vpn_state_temporary")
	_, err = out.Write(append(bytes, '\n'))
	if err == nil {
		err = out.Sync()
	}
	closed := out.Close()
	if err != nil || closed != nil {
		return fault("vpn_state_write_failed")
	}
	if unix.Renameat(fd, temporary, fd, "state.json") != nil || unix.Fsync(fd) != nil {
		return fault("vpn_state_sync_failed")
	}
	return nil
}
