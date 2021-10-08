package pollen

import (
	"bufio"
	"bytes"
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

	tbody := append([]byte{byte(len(topic))}, []byte(topic)...)
	tbody = append(tbody, body...)
	if _, err := p.conn.Write(pkg.FIXED_PUBLISH.Encode(tbody)); err != nil {
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
		if conn, err := net.DialTimeout("tcp", addr, 5*time.Second); err != nil {
			zap.L().Error(err.Error())
		} else {
			if err := p.connect(conn.(*net.TCPConn)); err != nil {
				goto NEXT
			}
			p.handle(conn.(*net.TCPConn))
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
	if _, err := conn.Write(pkg.FIXED_CONNECT.Encode(b)); err != nil {
		zap.L().Error(err.Error())
		return err
	}
	return nil
}

func (p *Pollen) handle(conn *net.TCPConn) {
	reader := bufio.NewReader(conn)
	var (
		offset,
		varintLen,
		size int
		code byte
	)

	buf := &bytes.Buffer{}
	buf.Reset()
	for {
		conn.SetReadDeadline(time.Now().Add(p.opt.ReadTimeout))
		b, err := reader.ReadByte()
		if err != nil {
			conn.Close()
			zap.L().Error(err.Error())
			return
		}

		buf.WriteByte(b)
		offset++
		if code == 0 {
			code = b
			if pkg.Fixed(code) == pkg.FIXED_PONG {
				offset, varintLen, size, code = 0, 0, 0, 0
				buf.Reset()
			}
			continue
		}
		if varintLen == 0 {
			px, pn := pkg.DecodeVarint(buf.Bytes()[1:])
			size = int(px) + pn
			if size == 0 {
				continue
			}
			varintLen = pn
			continue
		}

		if offset == size+1 && size != 0 {
			p.typeHandle(pkg.Fixed(code), conn, varintLen, buf)
			buf.Reset()
			offset, varintLen, size, code = 0, 0, 0, 0
			continue
		}
	}
}

func (p *Pollen) typeHandle(t pkg.Fixed, conn *net.TCPConn, varintLen int, buf *bytes.Buffer) {
	switch t {
	case pkg.FIXED_CONNACK:
		p.rwmutex.Lock()
		p.conn = conn
		p.rwmutex.Unlock()

		go p.ping()

		go p.submitSubscribe()
		if callback.Callback.ConnAck != nil {
			pb := &corepb.ConnAck{}
			if err := proto.Unmarshal(buf.Bytes()[1+varintLen:], pb); err != nil {
				zap.L().Error(err.Error())
			}

			callback.Callback.ConnAck(conn.LocalAddr().String(), conn.RemoteAddr().String(), pb)
		}
	case pkg.FIXED_PONG:
		if callback.Callback.Pong != nil {
			callback.Callback.Pong(conn.RemoteAddr().String())
		}
	case pkg.FIXED_PUBLISH:
		p.pubHandle(varintLen, buf)
	default:
		zap.L().Error("error data")
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

func (p *Pollen) pubHandle(varintLen int, buf *bytes.Buffer) {
	tl := buf.Bytes()[2+varintLen]
	topic := string(buf.Bytes()[3+varintLen : 3+varintLen+int(tl)])
	if v := p.subscribe.Get(topic); v != nil {
		v(buf.Bytes())
	}
}
