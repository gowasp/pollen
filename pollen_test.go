package pollen

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/gowasp/corepb"
	"github.com/gowasp/pollen/callback"
	"github.com/tnngo/lad"
)

func TestPollen_Subscribe(t *testing.T) {
	l, _ := lad.NewDevelopment()
	lad.ReplaceGlobals(l)

	p := New()
	p.Subscribe("a/b", func(b []byte) error {
		lad.L().Debug(string(b))
		return nil
	})
	p.Subscribe("c/d", func(b []byte) error {
		lad.L().Debug(string(b))
		return nil
	})
	p.Subscribe("e/f", func(b []byte) error {
		lad.L().Debug(string(b))
		return nil
	})

	callback.Callback.ConnAck = func(s1, s2 string, ca *corepb.ConnAck) {
		lad.S().Debug(ca.Time)

	}

	p.opt.UDID = "95270ee2-ce17-4de5-b12b-f3d0a40c387d"
	p.opt.Username = "123"
	p.opt.Password = "abcdef"

	key := hmac.New(sha256.New, []byte(p.opt.Username))

	// value
	value := []byte(p.opt.Username + "." + p.opt.Password)

	key.Write(value)
	r := key.Sum(nil)

	// base64 编码
	b64 := base64.RawStdEncoding.EncodeToString([]byte(r))

	p.opt.Password = b64
	p.Dial("localhost:6000")
}

func TestPollen_Publish(t *testing.T) {
	l, _ := lad.NewDevelopment()
	lad.ReplaceGlobals(l)

	p := New()
	p.opt.Username = "123"
	p.opt.Password = "abcdef"

	key := hmac.New(sha256.New, []byte(p.opt.Username))

	// value
	value := []byte(p.opt.Username + "." + p.opt.Password)

	key.Write(value)
	r := key.Sum(nil)

	// base64 编码
	b64 := base64.RawStdEncoding.EncodeToString([]byte(r))

	p.opt.Password = b64

	callback.Callback.ConnAck = func(s1, s2 string, ca *corepb.ConnAck) {
		lad.S().Debug(ca.Time)
	}
	go p.Dial("localhost:6000")
	time.Sleep(2 * time.Second)

	if err := p.Publish("a/b", []byte("pollen1")); err != nil {
		lad.L().Error(err.Error())
	}
	p.Publish("c/d", []byte{1, 2})
	p.Publish("e/f", []byte{3, 4})
	select {}
}
