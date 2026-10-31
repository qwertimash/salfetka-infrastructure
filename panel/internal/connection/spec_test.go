package connection

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func sample(id string) Spec {
	s := Spec{Template: id, Version: 1, Host: "node.example", ListenIP: "0.0.0.0", Port: 443, ServerName: "node.example"}
	if id == GRPC {
		s.ServiceName = "vpn"
	}
	if id == XHTTP {
		s.Path = "/vpn"
	}
	return s
}
func TestAllocatePreservesExplicitPortsAndProtocolIsolation(t *testing.T) {
	a, b := sample(GRPC), sample(Hy2)
	a.Port = 0
	b.Port = 0
	wanted := []Spec{a, b}
	occupied := []Listener{{"0.0.0.0", 8443, "tcp"}, {"::", 8444, "tcp"}, {"0.0.0.0", 443, "tcp"}}
	got, e := Allocate(wanted, occupied)
	if e != nil || got[0].Port != 8445 || got[1].Port != 443 {
		t.Fatal(got, e)
	}
	again, e := Allocate(wanted, occupied)
	if e != nil || !reflect.DeepEqual(got, again) || wanted[0].Port != 0 {
		t.Fatal("mutation or nondeterminism")
	}
	a.Port = 8443
	if _, e = Allocate([]Spec{a}, occupied); !errors.Is(e, ErrPort) {
		t.Fatal(e)
	}
	if !Conflicts(Listener{"::", 443, "tcp"}, Listener{"127.0.0.1", 443, "tcp"}) || Conflicts(Listener{"127.0.0.1", 443, "tcp"}, Listener{"127.0.0.2", 443, "tcp"}) {
		t.Fatal("bind conflict")
	}
}
func TestTemplateRejectsMixedAndInjectedFields(t *testing.T) {
	for _, id := range []string{Hy2, GRPC, XHTTP} {
		s := sample(id)
		if e := s.Validate(); e != nil {
			t.Fatal(id, e)
		}
		s.RealityTarget = "example.com:443"
		if s.Validate() == nil {
			t.Fatal("mixed security accepted")
		}
	}
	for _, path := range []string{"/../x", "/x?y", "/x\ny", "//x", "/"} {
		s := sample(XHTTP)
		s.Path = path
		if s.Validate() == nil {
			t.Fatal(path)
		}
	}
	for _, host := range []string{"example.com\ncommand", "host:443", "https://host", "[::1]", "fe80::1%en0"} {
		s := sample(GRPC)
		s.Host = host
		if s.Validate() == nil {
			t.Fatal(host)
		}
	}
	s := sample(GRPC)
	s.Version = 2
	if s.Validate() == nil {
		t.Fatal("future version accepted")
	}
}
func TestRealityKeyBindingAndClientSecretSeparation(t *testing.T) {
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s := sample(Reality)
	s.RealityTarget = "example.com:443"
	s.RealityShortID = "12ab"
	s.RealityPublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	c := Configuration{s, PrivateMaterial{RealityPrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes())}}
	if c.Validate() != nil {
		t.Fatal("valid key rejected")
	}
	out, e := s.ClientOutbound("test-credential", "")
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), c.Private.RealityPrivateKey) || strings.Contains(string(raw), "privateKey") {
		t.Fatal("secret in client")
	}
	c.Private.RealityPrivateKey = strings.Repeat("a", 43)
	if c.Validate() == nil {
		t.Fatal("unbound private key")
	}
}
