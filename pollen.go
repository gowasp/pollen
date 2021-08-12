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

// func (p *Pollen) Handle(code hornet.PkgType, hconn hornet.Conn, body []byte) {
// 	switch code {
// 	case hornet.CONNACK:
// 		p.connAck(hconn, body)
// 	case hornet.PONG:
// 		if p.featurer != nil {
// 			p.featurer.Pong()
// 		}
// 	case hornet.PUBLISH:
// 		if body == nil {
// 			zap.L().Error("ROUTE body is null", zap.String("sid", hconn.SID()), zap.String("remote_addr", hconn.RemoteAddr().String()))
// 			return
// 		}

// 		if p.featurer != nil {
// 			topic := string(body[:body[1]-1])
// 			if f := p.sub.get(topic); f != nil {
// 				f(body[body[1]:])
// 			}
// 		}
// 	case hornet.PVTPUBLISH:
// 		topic := string(body[:body[1]-1])
// 		if v := p.getPvtSubscribe(topic); v != nil {
// 			v(body[body[1]:])
// 		}
// 	default:
// 		zap.L().Warn("Unsupported protocol type", zap.Int("code", int(code)))
// 	}
// }

// func (p *Pollen) connAck(hconn hornet.Conn, body []byte) {
// 	p.mutex.Lock()
// 	p.hconn = hconn
// 	p.mutex.Unlock()

// 	if p.featurer != nil {
// 		p.featurer.ConnAck(hconn.RemoteAddr().String(), hconn.LocalAddr().String(), body)
// 	}

// 	go p.ping()
// }

// func (p *Pollen) ping() {
// 	if p.pingRate < 1 {
// 		p.pingRate = pingRate
// 	}

// 	pingByte := []byte{byte(hornet.PING), 0}
// 	for {
// 		if _, err := p.hconn.Write(pingByte); err != nil {
// 			zap.L().Error(err.Error())
// 			p.hconn.Close()
// 			return
// 		}

// 		time.Sleep(p.pingRate)
// 	}
// }

// var (
// 	ErrConnNotReady = errors.New("Connection not ready")
// )

// func (p *Pollen) PvtSubscribe(topic string, f privateFunc) {
// 	p.psMap.Store(topic, f)
// }

// func (p *Pollen) PvtPublish(body []byte, topic string) error {
// 	if p.hconn == nil {
// 		return ErrConnNotReady
// 	}

// 	payloadBody := append([]byte{byte(len(topic))}, topic...)
// 	payloadBody = append(payloadBody, body...)

// 	varintLen := hornet.EncodeVarint(len(payloadBody))
// 	varintLen = append(varintLen, payloadBody...)

// 	pbody := append([]byte{byte(hornet.PVTPUBLISH)}, varintLen...)

// 	if _, err := p.hconn.Write(pbody); err != nil {
// 		return err
// 	}

// 	return nil
// }
