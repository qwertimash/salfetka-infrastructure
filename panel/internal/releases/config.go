package releases

import (
	"encoding/json"
	"salfetka/panel/internal/nodes"
)

func nodeConfig(e nodes.VPNEndpoint, key string) json.RawMessage { return nodes.ClientConfig(e, key) }
