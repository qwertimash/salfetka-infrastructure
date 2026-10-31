package nodes

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/roomroute"
	"strings"
	"testing"
)

func TestPersonalRoomPublicationAndSignedPolicyAgree(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	install, _ := database.NewID()
	ep := VPNEndpoint{PersonalRooms: true, AccountSession: true, Backend: "olcrtc", Provider: "jitsi", Transport: "vp8channel", Room: "https://room.example.invalid/base/template", BootstrapDNS: "1.1.1.1:53"}
	if !ep.Valid() {
		t.Fatal("invalid personal endpoint")
	}
	if e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.ConfigureVPNTx(ctx, tx, f.m(n, "personal-install"), install, access.DefaultGroupID, true, &ep)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	u, grant := seedVPNUser(t, f)
	request := VPNFetch{SchemaVersion: 1, NodeID: n.ID, InstallationID: install, EngineEpoch: strings.Repeat("a", 32), Backend: "olcrtc", ProfileSHA256: ep.ProfileSHA256()}
	first, _, e := f.s.VPNDesired(ctx, cert, request)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	policy, e := nodecontrol.VerifyVPN(pub, *first.Policy)
	if e != nil || len(policy.Grants) != 0 {
		t.Fatal("unreserved account admitted", e)
	}
	var raw, rotated []byte
	if e = f.tx(func(tx pgx.Tx) error {
		var e error
		raw, e = PersonalClientConfig(ctx, tx, ep, strings.Repeat("a", 64), install, u, true)
		if e != nil {
			return e
		}
		rotated, e = PersonalClientConfig(ctx, tx, ep, strings.Repeat("b", 64), install, u, true)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	var a, b struct {
		Room    string
		Key     string `json:"key_hex"`
		Account bool   `json:"account_session"`
	}
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal(rotated, &b) != nil || a.Room != b.Room || a.Key == b.Key || !a.Account {
		t.Fatal("unstable room or lost account capability")
	}
	next, _, e := f.s.VPNDesired(ctx, cert, request)
	if e != nil {
		t.Fatal(e)
	}
	policy, e = nodecontrol.VerifyVPN(pub, *next.Policy)
	if e != nil || len(policy.Grants) != 1 || policy.Grants[0].ID != grant || policy.Grants[0].AccountID != u {
		t.Fatal("missing bound grant", e)
	}
	room, e := roomroute.URL(ep.Room, policy.Grants[0].RoomID)
	if e != nil || room != a.Room {
		t.Fatal("catalog/policy mismatch")
	}
	if ClientConfig(ep, strings.Repeat("a", 64)) != nil {
		t.Fatal("unsafe shared-room fallback")
	}
	other, _ := seedVPNUser(t, f)
	if e = f.tx(func(tx pgx.Tx) error {
		raw, e := PersonalClientConfig(ctx, tx, ep, strings.Repeat("c", 64), install, other, true)
		if e != nil {
			return e
		}
		var c struct{ Room string }
		if json.Unmarshal(raw, &c) != nil || c.Room == a.Room {
			t.Fatal("different users shared room")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestPersonalRoomsRequireAccountCapability(t *testing.T) {
	ep := VPNEndpoint{PersonalRooms: true, Backend: "olcrtc", Provider: "jitsi", Transport: "vp8channel", Room: "https://room.example.invalid/template", BootstrapDNS: "1.1.1.1:53"}
	if ep.Valid() {
		t.Fatal("personal rooms without account fencing")
	}
	ep.AccountSession = true
	for _, bad := range []string{"https://room.example.invalid/x?key=secret", "https://room.example.invalid/x#secret"} {
		ep.Room = bad
		if ep.Valid() {
			t.Fatal("ambiguous template accepted")
		}
	}
}
