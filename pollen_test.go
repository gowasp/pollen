package pollen

import (
	"testing"
	"time"

	"github.com/gowasp/corepb"
	"github.com/gowasp/pkg/pact"
	"github.com/gowasp/pollen/callback"
	"go.uber.org/zap"
)

func TestPollen_Dial(t *testing.T) {
	l, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(l)

	callback.Callback.ConnAck = func(ca *corepb.ConnAck) {
		zap.S().Debug(ca.GetTime())
	}

	callback.Callback.PvtPublishAck = func(i int) {
		zap.S().Debug(i)
	}
	p := New()
	go p.Dial("localhost:6000")
	time.Sleep(3 * time.Second)

	x := int(time.Now().Unix())
	zap.S().Debug(x)
	y := pact.EncodeVarint(x)

	a := append([]byte{1}, []byte("pollen")...)
	y = append(y, a...)
	c := append(pact.EncodeVarint(len(y)), y...)
	d := append([]byte{byte(pact.PVTPUBLISH)}, c...)
	if _, err := p.conn.Write(d); err != nil {
		t.Error(err)
		return
	}

	select {}
}
