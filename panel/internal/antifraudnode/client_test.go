package antifraudnode

import (
 "context"
 "crypto/tls"
 "encoding/json"
 "errors"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"
 "time"
)
func fixture(t *testing.T,h http.Handler)*Client{
 t.Helper();s:=httptest.NewTLSServer(h);t.Cleanup(s.Close)
 c,err:=New(s.URL,&tls.Config{Certificates:[]tls.Certificate{{}},MinVersion:tls.VersionTLS12},strings.Repeat("d",48),map[string]string{"key-a":"a","key-b":"b"});if err!=nil{t.Fatal(err)}
 c.http.Transport=s.Client().Transport // fixture CA only; live mTLS exercised by engine test
 t.Cleanup(c.Close);c.accounts["a"].known=true;c.accounts["a"].policy=policy{Account:"a",Revision:1,Limited:true};c.accounts["b"].known=true
 return c
}
func TestOutagePausesOnlyLimitedAccountAndRecovers(t *testing.T){
 var restored atomic.Bool;var calls atomic.Int64
 c:=fixture(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls.Add(1);if !restored.Load(){w.WriteHeader(503);return}
  var body struct{Sequence int64 `json:"sequence"`;Bytes int `json:"bytes"`};json.NewDecoder(r.Body).Decode(&body)
  now:=time.Now().UnixNano();json.NewEncoder(w).Encode(map[string]any{"limited":true,"status":"permit","revision":1,"sequence":body.Sequence,"bytes":body.Bytes,"send_at_ns":now+10e6,"expires_ns":now+150e6,"server_ns":now})
 }))
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
 done:=make(chan error,1);go func(){done<-c.Wait(ctx,"key-a","download",1000)}()
 until:=time.Now().Add(time.Second);for calls.Load()==0&&time.Now().Before(until){time.Sleep(time.Millisecond)}
 if calls.Load()==0{t.Fatal("no reservation attempted")}
 select{case<-done:t.Fatal("outage passed or disconnected A");default:}
 before:=calls.Load();if err:=c.Wait(ctx,"key-b","upload",1000);err!=nil{t.Fatal(err)};if calls.Load()!=before{t.Fatal("normal B depended on controller")}
 restored.Store(true);select{case err:=<-done:if err!=nil{t.Fatal(err)};case<-ctx.Done():t.Fatal("recovery failed")}
}
func TestCancellationMalformedAndStaleNeverAllowTraffic(t *testing.T){
 for _,mode:=range []string{"unavailable","malformed","stale"}{t.Run(mode,func(t *testing.T){
  c:=fixture(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){switch mode{case"unavailable":w.WriteHeader(503);case"malformed":w.Write([]byte(`{}`));case"stale":w.WriteHeader(409);w.Write([]byte(`{"error":"stale_node_session"}`))}}))
  ctx,cancel:=context.WithTimeout(context.Background(),30*time.Millisecond);defer cancel()
  err:=c.Wait(ctx,"key-a","upload",10)
  if err==nil{t.Fatal("traffic allowed")};if mode=="unavailable"&&!errors.Is(err,context.DeadlineExceeded){t.Fatal(err)}
 })}
}
func TestUnknownAndIncompleteSnapshotsCannotClearPolicy(t *testing.T){
 c:=fixture(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Write([]byte(`{"commands":[{"account_id":"a","revision":2,"budget_scope":"account_all_nodes_upload_plus_download"}]}`))}))
 if c.Sync(context.Background())==nil{t.Fatal("missing limited accepted")}
 if !c.accounts["a"].policy.Limited{t.Fatal("partial snapshot cleared policy")}
 if c.Wait(context.Background(),"unbound","upload",1)!=ErrInvalid{t.Fatal("unbound identity")}
 c.accounts["a"].waiting.Store(128)
 if c.Wait(context.Background(),"key-a","upload",1)!=ErrQueue{t.Fatal("unbounded queue")}
}
func TestExpiredPermitRetryAndSequenceAdvance(t *testing.T){
 var count int;var sequences []int64
 c:=fixture(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){var b struct{Sequence int64 `json:"sequence"`};json.NewDecoder(r.Body).Decode(&b);sequences=append(sequences,b.Sequence);count++
 if count==1{w.WriteHeader(409);w.Write([]byte(`{"error":"permit_expired"}`));return};w.Write([]byte(`{"limited":false,"revision":2}`))
 }))
 if err:=c.Wait(context.Background(),"key-a","download",12);err!=nil{t.Fatal(err)}
 if len(sequences)!=2||sequences[1]!=sequences[0]+1{t.Fatal(sequences)}
}
