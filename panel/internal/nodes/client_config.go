package nodes

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/roomroute"
	"strings"
)

func ClientConfig(endpoint VPNEndpoint, key string) json.RawMessage {
	if endpoint.Connection != nil {
		if !endpoint.Valid() {
			return nil
		}
		out, err := endpoint.Connection.ClientOutbound(key, endpoint.TrustedCAPEM)
		if err != nil {
			return nil
		}
		raw, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "warning"}, "outbounds": []any{out}})
		return raw
	}
	if endpoint.PersonalRooms {
		return nil
	}
	if endpoint.Backend == "olcrtc" {
		config := map[string]any{"provider": endpoint.Provider, "transport": endpoint.Transport, "room": endpoint.Room, "bootstrap_dns": endpoint.BootstrapDNS, "key_hex": key}
		if endpoint.AccountSession {
			config["account_session"] = true
		}
		b, _ := json.Marshal(config)
		return b
	}
	tls := map[string]any{"serverName": endpoint.ServerName, "allowInsecure": false, "alpn": []string{"http/1.1"}}
	if endpoint.TrustedCAPEM != "" {
		tls["disableSystemRoot"] = true
		tls["certificates"] = []any{map[string]any{"usage": "verify", "certificate": strings.Split(strings.TrimSpace(endpoint.TrustedCAPEM), "\n")}}
	}
	c := map[string]any{"log": map[string]any{"loglevel": "warning"}, "outbounds": []any{map[string]any{"tag": "vpn", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": endpoint.Host, "port": endpoint.Port, "users": []any{map[string]any{"id": key, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": tls}}}}
	if endpoint.Backend == "hysteria2" {
		tls["alpn"] = []string{"h3"}
		c["outbounds"] = []any{map[string]any{"tag": "vpn", "protocol": "hysteria", "settings": map[string]any{"version": 2, "address": endpoint.Host, "port": endpoint.Port}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "tlsSettings": tls, "hysteriaSettings": map[string]any{"version": 2, "auth": key}}}}
	}
	b, _ := json.Marshal(c)
	return b
}

// PersonalClientConfig uses the same durable binding as signed policy issuance.
// reserve is allowed only while staging an authorized subscription.
func PersonalClientConfig(ctx context.Context, tx pgx.Tx, endpoint VPNEndpoint, key, installation, user string, reserve bool) (json.RawMessage, error) {
	if !endpoint.PersonalRooms {
		return ClientConfig(endpoint, key), nil
	}
	var room string
	var err error
	if reserve {
		room, err = roomroute.Reserve(ctx, tx, installation, user)
	} else {
		room, err = roomroute.Lookup(ctx, tx, installation, user)
	}
	if err != nil {
		return nil, err
	}
	endpoint.Room, err = roomroute.URL(endpoint.Room, room)
	if err != nil {
		return nil, err
	}
	endpoint.PersonalRooms = false
	return ClientConfig(endpoint, key), nil
}
