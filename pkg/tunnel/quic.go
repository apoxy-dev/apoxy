package tunnel

import (
	"time"

	"github.com/quic-go/quic-go"
)

const ApplicationCodeOK quic.ApplicationErrorCode = 0x0

var quicConfig *quic.Config = &quic.Config{
	EnableDatagrams:                true,
	InitialPacketSize:              1350,
	InitialConnectionReceiveWindow: 5 * 1000 * 1000,
	MaxConnectionReceiveWindow:     100 * 1000 * 1000,
	KeepAlivePeriod:                1 * time.Second,
	MaxIdleTimeout:                 15 * time.Second,
}
