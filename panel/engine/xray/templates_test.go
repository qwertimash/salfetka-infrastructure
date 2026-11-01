package xrayengine

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	reality "github.com/xtls/reality"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodesite"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagedTemplatesRealTrafficAndIndependentRevoke(t *testing.T) {
	for _, id := range []string{connection.Reality, connection.Hy2, connection.GRPC, connection.XHTTP} {
		t.Run(id, func(t *testing.T) {
			ca := syntheticCert(t)
			p := freePort(t, id == connection.Hy2)
			spec := connection.Spec{Template: id, Version: 1, Host: "127.0.0.1", ListenIP: "127.0.0.1", Port: p, ServerName: "b0.invalid"}
			secret := connection.PrivateMaterial{CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n")}
			if id == connection.GRPC {
				spec.ServiceName = "vpn"
			}
			if id == connection.XHTTP {
				spec.Path = "/vpn"
			}
			if id == connection.Reality {
				dir := t.TempDir()
				if e := os.WriteFile(filepath.Join(dir, "bundle.pem"), []byte(secret.CertificatePEM+"\n"+secret.KeyPEM), 0600); e != nil {
					t.Fatal(e)
				}
				target := httptest.NewUnstartedServer(nodesite.Handler("b0.invalid", dir))
				target.EnableHTTP2 = true
				target.TLS = nodesite.TLS(dir, "b0.invalid")
				target.StartTLS()
				t.Cleanup(target.Close)
				k, e := ecdh.X25519().GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				spec.RealityTarget = target.Listener.Addr().String()
				spec.RealityPublicKey = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
				spec.RealityShortID = "1234abcd"
				secret = connection.PrivateMaterial{RealityPrivateKey: base64.RawURLEncoding.EncodeToString(k.Bytes())}
			}
			r, e := New(Config{Connection: &connection.Configuration{Public: spec, Private: secret}, LabLoopbackOnly: true})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { r.Close() })
			if id == connection.Reality {
				// REALITY probes its target asynchronously before serving traffic.
				// Wait for the actual probe, never seed or bypass the detection cache.
				until := time.Now().Add(12 * time.Second)
				for {
					v, _ := reality.GlobalPostHandshakeRecordsLens.Load(spec.RealityTarget + " " + spec.ServerName + " 2")
					if _, ok := v.([]int); ok {
						break
					}
					if time.Now().After(until) {
						t.Fatal("REALITY target probe did not finish")
					}
					time.Sleep(20 * time.Millisecond)
				}
				roots := x509.NewCertPool()
				roots.AppendCertsFromPEM([]byte(strings.Join(ca.root, "\n")))
				conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(p), &tls.Config{RootCAs: roots, ServerName: "b0.invalid", MinVersion: tls.VersionTLS13})
				if err != nil {
					t.Fatal("own-domain Reality website fallback", err)
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.WriteString(conn, "GET / HTTP/1.1\r\nHost: b0.invalid\r\nConnection: close\r\n\r\n")
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					conn.Close()
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				conn.Close()
				if response.StatusCode != 200 || !strings.Contains(string(body), "Field notes") {
					t.Fatal("website unavailable through Reality")
				}
			}
			tcp, udp := echoes(t)
			ga := Grant{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: time.Now().Add(time.Minute)}
			gb := ga
			gb.ID = users[1].Secret
			gb.Credential = users[1].Secret
			apply(t, r, ga)
			apply(t, r, gb)
			client := func(key string) *engine {
				out, e := spec.ClientOutbound(key, strings.Join(ca.root, "\n"))
				if e != nil {
					t.Fatal(e)
				}
				return startEngine(t, map[string]any{"outbounds": []any{out}})
			}
			a, b := client(ga.Credential), client(gb.Credential)
			at, bt := openFlow(t, a, "tcp", tcp), openFlow(t, b, "tcp", tcp)
			au, bu := openFlow(t, a, "udp", udp), openFlow(t, b, "udp", udp)
			check(t, at.exchange([]byte("a-tcp")) && bt.exchange([]byte("b-tcp")) && au.exchange([]byte("a-udp")) && bu.exchange([]byte("b-udp")), "template data exchange")
			u, e := r.Usage(ga.ID)
			check(t, e == nil && u.Uplink != nil && u.Downlink != nil && *u.Uplink > 0 && *u.Downlink > 0, "template usage")
			apply(t, r, Grant{ID: ga.ID, Generation: 2})
			check(t, !at.exchange([]byte("revoked")) && !au.exchange([]byte("revoked")), "A retained active traffic")
			check(t, bt.exchange([]byte("B-survives")) && bu.exchange([]byte("B-survives")), "A revoke interrupted B")
			check(t, !one(t, a, "tcp", tcp), "revoked saved credential reconnected")
		})
	}
}
