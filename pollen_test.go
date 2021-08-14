package pollen

import (
	"context"
	"testing"
	"time"

	"github.com/gowasp/corepb"
	"github.com/gowasp/pkg"
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
	y := pkg.EncodeVarint(x)

	a := append([]byte{1}, []byte("pollen")...)
	y = append(y, a...)
	c := append(pkg.EncodeVarint(len(y)), y...)
	d := append([]byte{byte(pkg.FIXED_PVTPUBLISH)}, c...)
	if _, err := p.conn.Write(d); err != nil {
		t.Error(err)
		return
	}

	select {}
}

func TestPollen_Subscribe(t *testing.T) {
	l, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(l)

	p := New()
	p.Subscribe("a/b", func(c context.Context, b []byte) error {
		zap.L().Debug(string(b))
		return nil
	})
	p.Subscribe("c/d", func(c context.Context, b []byte) error {
		zap.L().Debug(string(b))
		return nil
	})
	p.Subscribe("e/f", func(c context.Context, b []byte) error {
		zap.L().Debug(string(b))
		return nil
	})

	callback.Callback.ConnAck = func(ca *corepb.ConnAck) {
		zap.S().Debug(ca.Time)
		p.SubmitSubscribe()
	}
	p.Dial("localhost:6000")
}

func TestPollen_Publish(t *testing.T) {
	l, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(l)
	p := New()

	callback.Callback.ConnAck = func(ca *corepb.ConnAck) {
		zap.S().Debug(ca.Time)
	}

	go p.Dial("localhost:6000")
	time.Sleep(1 * time.Second)

	if err := p.Publish("a/b", []byte("pollen1")); err != nil {
		zap.L().Error(err.Error())
	}
	p.Publish("c/d", []byte("pollen2"))
	p.Publish("e/f", []byte("pollen3"))
	select {}
}
