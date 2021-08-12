package pollen

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"github.com/gowasp/corepb"
	"github.com/gowasp/pkg/pact"
	"github.com/gowasp/pollen/callback"
	"go.uber.org/zap"
)

type Option struct {
	UDID, Username, Group, Password string

	ReadTimeout, PingRate time.Duration
}

type Pollen struct {
	opt         *Option
	haveConnect bool
	conn        *net.TCPConn

	rwmutex sync.RWMutex
}

func New() *Pollen {
	return &Pollen{
		opt: &Option{
			UDID: uuid.New().String(),
		},
	}
}

func NewOpt(opt *Option) *Pollen {
	return &Pollen{
		opt: opt,
	}
}

func (p *Pollen) Dial(addr string) {
	if p.opt.ReadTimeout < 1 {
		p.opt.ReadTimeout = 5 * 60 * time.Second
	}

	raddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		zap.L().Error(err.Error())
		return
	}

	for {
		if conn, err := net.DialTCP("tcp", nil, raddr); err != nil {
			zap.L().Error(err.Error())
		} else {
			p.handle(conn)
		}
		time.Sleep(5 * time.Second)
	}
}

func (p *Pollen) handle(conn *net.TCPConn) {
	body := make([]byte, 4096)
	buf := &bytes.Buffer{}

	var (
		code byte

		offset, size, varintLen int
	)
	for {

		// set timeout.
		err := conn.SetReadDeadline(time.Now().Add(p.opt.ReadTimeout))
		if err != nil {
			return
		}

		if !p.haveConnect {
			pb := &corepb.Connect{
				Udid:     p.opt.UDID,
				Group:    p.opt.Group,
				Username: p.opt.Username,
				Password: p.opt.Password,
			}

			b, err := proto.Marshal(pb)
			if err != nil {
				zap.L().Error(err.Error())
				return
			}
			if _, err := conn.Write(pact.CONNECT.Encode(b)); err != nil {
				zap.L().Error(err.Error())
				return
			}
			p.haveConnect = true
		}

		n, err := conn.Read(body)
		if err != nil {
			conn.Close()
			return
		}

		buf.Write(body[:n])

		if offset == 0 {
			code = buf.Bytes()[0]
			size, varintLen = pact.DecodeVarint(buf.Bytes()[1:])
			offset = n - 1 - varintLen
			buf.Next(1 + varintLen)

			if size+varintLen+1 <= n {
				p.typeHandle(pact.Type(code), conn, buf.Next(size))
				buf.Reset()
				offset, size, varintLen = 0, 0, 0
				code = 0
			}
			continue
		}

		offset += n

		if offset < size {
			continue
		} else if offset == size {
			p.typeHandle(pact.Type(code), conn, buf.Next(size))
			buf.Reset()
			offset, size, varintLen = 0, 0, 0
			code = 0
		} else {
			p.typeHandle(pact.Type(code), conn, buf.Next(size))
			offset, size, varintLen = 0, 0, 0
			code = 0
		}
	}
}

func (p *Pollen) typeHandle(t pact.Type, conn *net.TCPConn, body []byte) {
	switch t {
	case pact.CONNACK:
		if callback.Callback.ConnAck != nil {
			pb := &corepb.ConnAck{}
			if err := proto.Unmarshal(body, pb); err != nil {
				zap.L().Error(err.Error())
				return
			}

			p.rwmutex.Lock()
			p.conn = conn
			p.rwmutex.Unlock()
			go p.ping()
			callback.Callback.ConnAck(pb)
		}
	case pact.PVTPUBACK:
		p.pvtPubAckHandle(body)
	}
}

func (p *Pollen) ping() {
	if p.opt.PingRate < 1 {
		p.opt.PingRate = 2 * 60 * time.Second
	}

	for {
		p.conn.Write([]byte{byte(pact.PING)})
		time.Sleep(p.opt.PingRate)
	}
}

func (w *Pollen) pvtPubAckHandle(body []byte) {
	v, _ := pact.DecodeVarint(body)
	if callback.Callback.PvtPublishAck != nil {
		callback.Callback.PvtPublishAck(v)
	} else {
		zap.S().Debugf("PVTPUBACK %d", v)
	}
}
