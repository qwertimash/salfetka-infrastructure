package trafficexport

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var ErrFile = errors.New("traffic_export_file_unsafe_or_unavailable")
var ErrBusy = errors.New("traffic_export_busy")

const SnapshotName = "snapshot.json"

// Publisher holds the directory lock across database read AND publication.
type Publisher struct{ dir, lock int }

func privateRegular(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0077 == 0 &&
		st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}

// Open never creates directories; the operator selects an existing private one.
func Open(path string) (*Publisher, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrFile
	}
	p := &Publisher{dir: fd, lock: -1}
	fail := func(e error) (*Publisher, error) { p.Close(); return nil, e }
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		return fail(ErrFile)
	}
	p.lock, err = unix.Openat(fd, ".export.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil || unix.Fstat(p.lock, &st) != nil || !privateRegular(&st) {
		return fail(ErrFile)
	}
	if unix.Flock(p.lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fail(ErrBusy)
	}
	return p, nil
}

func (p *Publisher) Close() {
	if p.lock >= 0 {
		unix.Close(p.lock)
		p.lock = -1
	}
	if p.dir >= 0 {
		unix.Close(p.dir)
		p.dir = -1
	}
}

func (p *Publisher) Write(raw []byte) error {
	if p.dir < 0 || len(raw) < 1 || len(raw) > MaxBytes {
		return ErrFile
	}
	var st unix.Stat_t
	err := unix.Fstatat(p.dir, SnapshotName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) || err == nil && !privateRegular(&st) {
		return ErrFile
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return ErrFile
	}
	name := ".snapshot-" + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := unix.Openat(p.dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrFile
	}
	defer unix.Unlinkat(p.dir, name, 0)
	f := os.NewFile(uintptr(fd), "traffic_snapshot")
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil || unix.Renameat(p.dir, name, p.dir, SnapshotName) != nil {
		return ErrFile
	}
	// Rename may have succeeded when fsync fails; cumulative replay is safe.
	if unix.Fsync(p.dir) != nil {
		return ErrFile
	}
	return nil
}
