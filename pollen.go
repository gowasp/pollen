package pollen

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"github.com/gowasp/corepb"
	"github.com/gowasp/pkg"
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
	subscribe   *pkg.Subscribe

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

func (p *Pollen) Opt() *Option {
	return p.opt
}

func (p *Pollen) Subscribe(topic string, f pkg.SubFunc) {
	if p.subscribe == nil {
		p.subscribe = &pkg.Subscribe{}
	}
	p.subscribe.Subscribe(topic, f)
}

var (
	ErrConnNotReady = errors.New("connection not ready")
)

func (p *Pollen) Publish(topic string, body []byte) error {
	p.rwmutex.RLock()
	defer p.rwmutex.RUnlock()
	if p.conn == nil {
		return ErrConnNotReady
	}
	if _, err := p.conn.Write(pkg.PubEncode(topic, body)); err != nil {
		return err
	}
	return nil
}

func (p *Pollen) SubmitSubscribe() error {
	strs := p.subscribe.GetTopics()
	if len(strs) == 0 {
		return nil
	}
	if p.conn == nil {
		return ErrConnNotReady
	}

	buf := &bytes.Buffer{}
	for _, v := range strs {
		sln := append([]byte(v), '\n')
		buf.Write(sln)
	}

	buf.Truncate(buf.Len() - 1)
	if _, err := p.conn.Write(pkg.FIXED_SUBSCRIBE.Encode(buf.Bytes())); err != nil {
		return err
	}
	return nil
}

func (p *Pollen) Dial(addr string) {
	if p.opt.ReadTimeout < 1 {
		p.opt.ReadTimeout = 5 * 60 * time.Second
	}

	var retryTime = 1 * time.Second
	for {
		raddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			zap.L().Error(err.Error())
			goto NEXT
		}

		if conn, err := net.DialTCP("tcp", nil, raddr); err != nil {
			zap.L().Error(err.Error())
		} else {
			if err := p.connect(conn); err != nil {
				goto NEXT
			}
			p.handle(conn)
		}

	NEXT:
		time.Sleep(retryTime)
		retryTime = retryTime + 1*time.Second

		if retryTime == 30*60*time.Second {
			retryTime = 1 * time.Second
		}
	}
}

func (p *Pollen) connect(conn *net.TCPConn) error {
	pb := &corepb.Connect{
		Udid:     p.opt.UDID,
		Group:    p.opt.Group,
		Username: p.opt.Username,
		Password: p.opt.Password,
	}

	b, err := proto.Marshal(pb)
	if err != nil {
		zap.L().Error(err.Error())
		return err
	}
	if _, err := conn.Write(pkg.FIXED_CONNECT.Encode(b)); err != nil {
		zap.L().Error(err.Error())
		return err
	}
	return nil
}

func (p *Pollen) handle(conn *net.TCPConn) {
	body := make([]byte, 4096)
	buf := &bytes.Buffer{}

	var (
		code byte

		size, varintLen int
	)
	for {

		// set timeout.
		err := conn.SetReadDeadline(time.Now().Add(p.opt.ReadTimeout))
		if err != nil {
			zap.L().Error(err.Error())
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
			if _, err := conn.Write(pkg.FIXED_CONNECT.Encode(b)); err != nil {
				zap.L().Error(err.Error())
				return
			}
			p.haveConnect = true
		}

		n, err := conn.Read(body)
		if err != nil {
			conn.Close()
			p.haveConnect = false
			zap.L().Error(err.Error())
			return
		}

		buf.Write(body[:n])

		for {
			if buf.Len() == 0 {
				break
			}
			if code == 0 {
				code = buf.Next(1)[0]
			}

			if code == byte(pkg.FIXED_PONG) {
				if err := p.typeHandle(pkg.Fixed(code), conn, nil); err != nil {
					conn.Close()
					return
				}
				code = 0
				continue
			}

			if varintLen == 0 {
				size, varintLen = pkg.DecodeVarint(buf.Bytes())
				buf.Next(varintLen)
			}

			if size == buf.Len() {
				if err := p.typeHandle(pkg.Fixed(code), conn, buf.Next(size)); err != nil {
					conn.Close()
					return
				}
				size, varintLen = 0, 0
				code = 0
				buf.Reset()
				break
			} else if size < buf.Len() {
				if err := p.typeHandle(pkg.Fixed(code), conn, buf.Next(size)); err != nil {
					conn.Close()
					return
				}
				size, varintLen = 0, 0
				code = 0
				continue
			} else {
				break
			}
		}
	}
}

func (p *Pollen) typeHandle(t pkg.Fixed, conn *net.TCPConn, body []byte) error {
	switch t {
	case pkg.FIXED_CONNACK:
		p.rwmutex.Lock()
		p.conn = conn
		p.rwmutex.Unlock()

		go p.ping()

		if callback.Callback.ConnAck != nil {
			pb := &corepb.ConnAck{}
			if err := proto.Unmarshal(body, pb); err != nil {
				zap.L().Error(err.Error())
				return errors.New("error data")
			}

			callback.Callback.ConnAck(conn.LocalAddr().String(), conn.RemoteAddr().String(), pb)
		}
		return nil
	case pkg.FIXED_PONG:
		if callback.Callback.Pong != nil {
			callback.Callback.Pong(conn.RemoteAddr().String())
		}
		return nil
	case pkg.FIXED_PUBLISH:
		if len(body) == 0 {
			return errors.New("error data")
		}
		if err := p.pubHandle(body); err != nil {
			conn.Close()
			return err
		}
		return nil
	case pkg.FIXED_PUBACK:
		p.pubAckHandle(body)
		return nil
	default:
		return errors.New("error data")
	}

}

func (p *Pollen) ping() {
	if p.opt.PingRate < 1 {
		p.opt.PingRate = 2 * 60 * time.Second
	}

	for {
		p.conn.Write([]byte{byte(pkg.FIXED_PING)})
		time.Sleep(p.opt.PingRate)
	}
}

func (p *Pollen) pubHandle(body []byte) error {
	seq, topic, newbody, err := pkg.PubDecodeSeq(body)
	if err != nil {
		return err
	}

	if v := p.subscribe.Get(topic); v != nil {
		ctx := context.WithValue(context.Background(), _CTXSEQ, seq)
		if err := v(ctx, newbody); err == nil {
			b := pkg.EncodeVarint(seq)
			if _, err := p.conn.Write(pkg.FIXED_PUBACK.Encode(b)); err != nil {
				zap.L().Error(err.Error())
			}
		}
	}
	return nil
}

func (p *Pollen) pubAckHandle(body []byte) {

	if callback.Callback.PubAck != nil {
		x, _ := pkg.DecodeVarint(body)
		callback.Callback.PubAck(x)
	}

}

type ctxString string

const (
	_CTXSEQ ctxString = "ctxSeq"
)

func GetCtxSeq(ctx context.Context) int {
	return ctx.Value(_CTXSEQ).(int)
}
