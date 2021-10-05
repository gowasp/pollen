package pollen

import (
	"bufio"
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

func (p *Pollen) submitSubscribe() error {
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
	if _, err := p.conn.Write(pkg.SubEncode(buf.Bytes())); err != nil {
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
			retryTime = 1 * time.Second
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
	if _, err := conn.Write(pkg.ConnectEncode(b)); err != nil {
		zap.L().Error(err.Error())
		return err
	}
	return nil
}

func (p *Pollen) handle(conn *net.TCPConn) {
	reader := bufio.NewReader(conn)
	buf := new(bytes.Buffer)
	var (
		offset    int
		varintLen int
		size      int
		code      byte

		//ctx context.Context
	)
	for {
		// set timeout.
		conn.SetReadDeadline(time.Now().Add(p.opt.ReadTimeout))
		for {
			b, err := reader.ReadByte()
			if err != nil {
				conn.Close()
				zap.L().Error(err.Error())
				return
			}

			if code == 0 {
				code = b
				if code == byte(pkg.FIXED_PONG) {
					offset, varintLen, size, code = 0, 0, 0, 0
				}
				continue
			}

			if varintLen == 0 {
				varintLen = int(b)
				continue
			}

			buf.WriteByte(b)
			offset++

			if offset == varintLen {
				px, pn := proto.DecodeVarint(buf.Next(offset))
				size = int(px) + pn
			}

			if offset == size && size != 0 {
				p.typeHandle(pkg.Fixed(code), conn, buf)

				buf.Reset()
				offset, varintLen, size, code = 0, 0, 0, 0
				break
			}
		}
	}
}

func (p *Pollen) typeHandle(t pkg.Fixed, conn *net.TCPConn, buf *bytes.Buffer) error {
	switch t {
	case pkg.FIXED_CONNACK:
		p.rwmutex.Lock()
		p.conn = conn
		p.rwmutex.Unlock()

		go p.ping()

		go p.submitSubscribe()
		if callback.Callback.ConnAck != nil {
			pb := &corepb.ConnAck{}
			if err := proto.Unmarshal(buf.Bytes(), pb); err != nil {
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
		if err := p.pubHandle(buf); err != nil {
			conn.Close()
			return err
		}
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
		if _, err := p.conn.Write([]byte{byte(pkg.FIXED_PING)}); err != nil {
			zap.L().Warn(err.Error())
			p.conn.Close()
			return
		}
		time.Sleep(p.opt.PingRate)
	}
}

func (p *Pollen) pubHandle(buf *bytes.Buffer) error {
	topicLen := buf.Next(1)[0]
	topic := string(buf.Next(int(topicLen)))
	if v := p.subscribe.Get(topic); v != nil {
		v(buf.Bytes())
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
