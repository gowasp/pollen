package callback

import "github.com/gowasp/corepb"

type callback struct {
	ConnAck func(*corepb.ConnAck)
	PubAck  func(int)

	PvtPublishAck func(int)
}

var (
	Callback = &callback{}
)
