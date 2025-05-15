package pollen

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/gowasp/corepb"
	"github.com/gowasp/pollen/callback"
	"github.com/ovixonlabs/lad"
)

func TestPollen_Subscribe(t *testing.T) {
	l, _ := lad.NewDevelopment()
	lad.ReplaceGlobals(l)

	p := New()
	p.Subscribe("flm/scale/test123456", func(b []byte) error {
		lad.L().Debug(string(b))
		return nil
	})
	// p.Subscribe("c/d", func(b []byte) error {
	// 	lad.L().Debug(string(b))
	// 	return nil
	// })
	// p.Subscribe("e/f", func(b []byte) error {
	// 	lad.L().Debug(string(b))
	// 	return nil
	// })

	callback.Callback.ConnAck = func(s1, s2 string, ca *corepb.ConnAck) {
		lad.S().Debug(ca.Time)

	}

	p.opt.UDID = "95270ee2-ce17-4de5-b12b-f3d0a40c387d"
	p.opt.Group = "test"
	p.opt.Username = "rO5vD0lY0sO0pP6r"
	p.opt.Password = "kM2oP7nJ3yY8oS8gR8jS1fT0lG2iA6qB"

	key := hmac.New(sha256.New, []byte(p.opt.Username))

	// value
	value := []byte(p.opt.Username + "." + p.opt.Password)

	key.Write(value)
	r := key.Sum(nil)

	// base64 编码
	b64 := base64.RawStdEncoding.EncodeToString([]byte(r))

	p.opt.Password = b64
	p.Dial("47.108.233.145:6002")
}

func TestPollen_Publish(t *testing.T) {
	l, _ := lad.NewDevelopment()
	lad.ReplaceGlobals(l)

	p := New()
	p.opt.UDID = "123"
	p.opt.Group = "test"
	p.opt.Username = "rO5vD0lY0sO0pP6r"
	p.opt.Password = "kM2oP7nJ3yY8oS8gR8jS1fT0lG2iA6qB"

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
	go p.Dial("47.108.233.145:6002")
	time.Sleep(2 * time.Second)

	// if err := p.Publish("a/b", []byte("pollen1")); err != nil {
	// 	lad.L().Error(err.Error())
	// }
	type A struct {
		Topic  string `json:"topic"`
		Params struct {
			Rate   float64 `json:"Rate"`
			Total  float64 `json:"Total"`
			STotal int     `json:"STotal"`
			Speed  int     `json:"Speed"`
			Kgm    int     `json:"Kgm"`
			Pulse  int     `json:"Pulse"`
			Mv1    int     `json:"mv1"`
			Mv2    int     `json:"mv2"`
		} `json:"params"`
	}

	a := &A{
		Topic: "flm/scale/test123456",
		Params: struct {
			Rate   float64 "json:\"Rate\""
			Total  float64 "json:\"Total\""
			STotal int     "json:\"STotal\""
			Speed  int     "json:\"Speed\""
			Kgm    int     "json:\"Kgm\""
			Pulse  int     "json:\"Pulse\""
			Mv1    int     "json:\"mv1\""
			Mv2    int     "json:\"mv2\""
		}{
			Rate:   12.300000,
			Total:  456.780000,
			STotal: 0,
			Speed:  1,
			Kgm:    4,
			Pulse:  50,
			Mv1:    10,
			Mv2:    11,
		},
	}

	b, _ := json.Marshal(a)
	p.Publish("flm/scale/test123456", b)
	// p.Publish("e/f", []byte{3, 4})
	select {}
}
