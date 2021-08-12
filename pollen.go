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
	private     *pkg.Private
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

func (p *Pollen) Private() *pkg.Private {
	if p.private == nil {
		p.private = &pkg.Private{}
	}
	return p.private
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

func (p *Pollen) Publish(seq int, topic string, body []byte) error {
	p.rwmutex.RLock()
	defer p.rwmutex.RUnlock()
	if p.conn == nil {
		return ErrConnNotReady
	}
	if _, err := p.conn.Write(pact.PubEncode(seq, topic, body)); err != nil {
		return err
	}
	return nil
}

func (p *Pollen) SubmitSubscribe() {
	strs := p.subscribe.GetTopics()
	if len(strs) == 0 {
		return
	}

	for _, v := range strs {
		zap.L().Debug(v)
		p.conn.Write(pact.SUBSCRIBE.Encode([]byte(v)))
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

		size, varintLen int
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

			if code == byte(pact.PING) {
				p.typeHandle(pact.Type(code), conn, nil)
				code = 0
				continue
			}

			size, varintLen = pact.DecodeVarint(buf.Bytes()[0:])
			buf.Next(varintLen)

			if size+varintLen+1 == n {
				p.typeHandle(pact.Type(code), conn, buf.Next(size))
				size, varintLen = 0, 0
				code = 0
				break
			}

			if size+varintLen+1 < n {
				p.typeHandle(pact.Type(code), conn, buf.Next(size))
				code = 0
				continue
			}
			break

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
	case pact.PUBLISH:
		p.pubHandle(body)
	case pact.PVTPUBLISH:
		p.pvtPubHandle(body)
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

func (p *Pollen) pubHandle(body []byte) {
	seq, topic, body := pact.PubDecode(body)

	if v := p.subscribe.Get(topic); v != nil {
		ctx := context.WithValue(context.Background(), _CTXSEQ, seq)
		v(ctx, body)
	}
}

func (p *Pollen) pvtPubHandle(body []byte) {
	seq, topicID, b := pact.PvtPubDecode(body)
	if v := p.private.Get(topicID); v != nil {
		ctx := context.WithValue(context.Background(), _CTXSEQ, seq)
		v(ctx, b)
	}
}

func (p *Pollen) pvtPubAckHandle(body []byte) {
	v, _ := pact.DecodeVarint(body)
	if callback.Callback.PvtPublishAck != nil {
		callback.Callback.PvtPublishAck(v)
	} else {
		zap.S().Debugf("PVTPUBACK %d", v)
	}
}

type ctxString string

const (
	_CTXSEQ ctxString = "ctxSeq"
)

func GetCtxSeq(ctx context.Context) int {
	return ctx.Value(_CTXSEQ).(int)
}
