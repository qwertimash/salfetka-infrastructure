package diagnostics

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
)

type Invitation struct {
	Code        string `json:"code"`
	TesterID    string `json:"tester_id"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
}
type Inviter interface {
	Invite(context.Context, string, string, string) (Invitation, error)
}

// New is called with a separate write key when used as Inviter. Its HTTP route
// is fixed; this does not add write authority to the existing Reader instance.
func (c *Client) Invite(ctx context.Context, account, name, request string) (Invitation, error) {
	var out Invitation
	if !uuid.MatchString(account) || len(request) < 16 || len(request) > 256 || len(name) > 320 {
		return out, ErrInvalid
	}
	mac := hmac.New(sha256.New, []byte(c.key))
	mac.Write([]byte("diagnostic-invite-v1\n" + account + "\n" + request))
	out.Code = hex.EncodeToString(mac.Sum(nil))
	requestHash := sha256.Sum256([]byte("diagnostic-request-v1\n" + account + "\n" + request))
	body, e := json.Marshal(map[string]string{"account_id": account, "name": name, "code": out.Code, "request_id": hex.EncodeToString(requestHash[:])})
	if e != nil {
		return out, ErrInvalid
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.origin+"/panel/v1/invitations", bytes.NewReader(body))
	if e != nil {
		return Invitation{}, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return Invitation{}, ErrUnavailable
	}
	res, e := c.http.Do(req)
	if e != nil {
		return Invitation{}, ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Invitation{}, ErrUnavailable
	}
	data, e := io.ReadAll(io.LimitReader(res.Body, 4097))
	if e != nil || len(data) > 4096 {
		return Invitation{}, ErrUnavailable
	}
	var receipt struct {
		TesterID    string `json:"tester_id"`
		ExpiresAtMS int64  `json:"expires_at_ms"`
	}
	if json.Unmarshal(data, &receipt) != nil || !uuid.MatchString(receipt.TesterID) || receipt.ExpiresAtMS < 1 {
		return Invitation{}, ErrUnavailable
	}
	out.TesterID = receipt.TesterID
	out.ExpiresAtMS = receipt.ExpiresAtMS
	return out, nil
}
