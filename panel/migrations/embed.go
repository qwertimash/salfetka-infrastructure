// Package migrations owns the ordered, immutable SQL migration inputs.
package migrations

import "embed"

// Files are embedded in each binary; startup never discovers SQL from disk.
//
//go:embed *.sql
var Files embed.FS
