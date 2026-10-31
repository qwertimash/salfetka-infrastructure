package nodes

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"strings"
	"testing"
)

func TestServerDomainValidation(t *testing.T) {
	for input, want := range map[string]string{"Pol.Example.COM.": "pol.example.com", "xn--e1afmkfd.example": "xn--e1afmkfd.example"} {
		if got, err := canonicalServerDomain(input); err != nil || got != want {
			t.Fatalf("domain %q: %q %v", input, got, err)
		}
	}
	for _, input := range []string{"", "localhost", "203.0.113.1", "https://pol.example.com", "pol.example.com:443", "*.example.com", "a..example.com", "-a.example.com", "a-.example.com", "a_b.example.com", "a/example.com", "пример.рф", strings.Repeat("a", 64) + ".example.com"} {
		if _, err := canonicalServerDomain(input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted domain %q", input)
		}
	}
}

func TestServerDomainPersistedAndBoundToRetry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	m := f.m(Node{}, "/servers")
	var first Server
	for i, domain := range []string{"Pol.Example.COM.", "pol.example.com"} {
		if err := f.tx(func(tx pgx.Tx) error {
			v, replay, err := f.s.CreateServerTx(ctx, tx, m, "Domain fixture", "203.0.113.10", domain)
			if err == nil && (v.Domain != "pol.example.com" || replay != (i == 1) || i == 1 && v.ID != first.ID) {
				t.Fatal("domain retry changed identity or name")
			}
			first = v
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.tx(func(tx pgx.Tx) error {
		_, _, err := f.s.CreateServerTx(ctx, tx, m, "Domain fixture", "203.0.113.10", "other.example.com")
		return err
	}); !errors.Is(err, ErrConflict) {
		t.Fatal("changed domain reused request", err)
	}
	if err := f.tx(func(tx pgx.Tx) error {
		p, err := f.s.ServersTx(ctx, tx, "")
		if err == nil && (len(p.Items) != 1 || p.Items[0].Domain != first.Domain) {
			t.Fatal("domain missing in list")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPhysicalServersSeparateConnectionsAndPersistConfigurationHistory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var server Server
	m := f.m(Node{}, "/servers")
	if e := f.tx(func(tx pgx.Tx) error {
		var e error
		server, _, e = f.s.CreateServerTx(ctx, tx, m, "Germany lab")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		again, replay, e := f.s.CreateServerTx(ctx, tx, m, "Germany lab")
		if !replay || again.ID != server.ID {
			t.Fatal("server create retry changed identity")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	makeNode := func(name string) Node {
		t.Helper()
		var n Node
		m := f.m(Node{}, "/servers/"+server.ID+"/connections")
		if e := f.tx(func(tx pgx.Tx) error {
			var e error
			n, _, e = f.s.CreateServerConnectionTx(ctx, tx, m, server.ID, name)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.p.Exec(ctx, "UPDATE nodes_registry SET state='active',serial=$2,public_key=decode(repeat('01',32),'hex'),certificate_expires_at=clock_timestamp()+interval '1 day' WHERE id=$1", n.ID, n.ID); e != nil {
			t.Fatal(e)
		}
		return n
	}
	first, second := makeNode("VLESS lab"), makeNode("Hysteria lab")
	endpoint := &VPNEndpoint{Host: "vpn.example.com", Port: 19443, ServerName: "vpn.example.com"}
	installation, _ := database.NewID()
	m = f.m(first, "vpn")
	configure := func(n Node, backend string) error {
		eid, _ := database.NewID()
		ep := *endpoint
		ep.Backend = backend
		return f.tx(func(tx pgx.Tx) error {
			_, _, e := f.s.ConfigureVPNTx(ctx, tx, f.m(n, "vpn"), eid, access.DefaultGroupID, true, &ep)
			return e
		})
	}
	if e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.ConfigureVPNTx(ctx, tx, m, installation, access.DefaultGroupID, true, endpoint)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := configure(second, ""); !errors.Is(e, ErrConflict) {
		t.Fatal("same TCP port accepted", e)
	}
	if e := configure(second, "hysteria2"); e != nil {
		t.Fatal("TCP/UDP unnecessarily collide", e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		_, replay, e := f.s.ConfigureVPNTx(ctx, tx, m, installation, access.DefaultGroupID, true, endpoint)
		if !replay {
			t.Fatal("lost-response retry not recognized")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		page, e := f.s.ServerConnectionsTx(ctx, tx, server.ID, "")
		if e != nil {
			return e
		}
		if len(page.Items) != 2 {
			t.Fatal("wrong server members")
		}
		history, e := f.s.VPNHistoryTx(ctx, tx, first.ID, 0)
		if e != nil {
			return e
		}
		if len(history) != 1 || history[0].Configuration.InstallationID != installation || history[0].Configuration.Endpoint.Port != 19443 {
			t.Fatal("config history missing or retry duplicated")
		}
		servers, e := f.s.ServersTx(ctx, tx, "")
		if e == nil && (len(servers.Items) != 1 || servers.Items[0].Connections != 2) {
			t.Fatal("incorrect inventory")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.p.Exec(ctx, "UPDATE nodes_vpn_config_versions SET revision=revision+1"); e == nil {
		t.Fatal("mutable config history")
	}
}

func TestServerAddressCanonicalizationAndRetryBinding(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	m := f.m(Node{}, "/servers")
	var created Server
	if e := f.tx(func(tx pgx.Tx) error {
		var e error
		created, _, e = f.s.CreateServerTx(ctx, tx, m, "Address fixture", "2001:db8:0:0::1")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if created.Address != "2001:db8::1" {
		t.Fatal("address not canonical")
	}
	if e := f.tx(func(tx pgx.Tx) error {
		v, replay, e := f.s.CreateServerTx(ctx, tx, m, "Address fixture", "2001:db8::1")
		if e == nil && (!replay || v.ID != created.ID) {
			t.Fatal("retry lost")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.CreateServerTx(ctx, tx, m, "Address fixture", "203.0.113.12")
		return e
	}); !errors.Is(e, ErrConflict) {
		t.Fatal("changed address reused request", e)
	}
	for _, address := range []string{"", "https://203.0.113.1", "203.0.113.1:443", "203.0.113.1/24", "fe80::1%en0", "0.0.0.0", "ff02::1"} {
		if e := f.tx(func(tx pgx.Tx) error {
			_, _, e := f.s.CreateServerTx(ctx, tx, f.m(Node{}, "/servers"), "Invalid address", address)
			return e
		}); !errors.Is(e, ErrInvalid) {
			t.Fatalf("accepted invalid address %q: %v", address, e)
		}
	}
	if e := f.tx(func(tx pgx.Tx) error {
		p, e := f.s.ServersTx(ctx, tx, "")
		if e == nil && (len(p.Items) != 1 || p.Items[0].Address != created.Address) {
			t.Fatal("address lost in list")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
