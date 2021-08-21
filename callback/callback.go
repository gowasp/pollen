package callback

import "github.com/gowasp/corepb"

type callback struct {
	ConnAck func(string, string, *corepb.ConnAck)
	Pong    func(string)
	PubAck  func(int)

	PvtPublishAck func(int)
}

var (
	Callback = &callback{}
)
