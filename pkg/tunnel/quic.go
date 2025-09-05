package tunnel

import (
	"time"

	"github.com/quic-go/quic-go"
)

const (
	ApplicationCodeOK            quic.ApplicationErrorCode = quic.ApplicationErrorCode(quic.NoError)
	ApplicationCodeInternalError quic.ApplicationErrorCode = quic.ApplicationErrorCode(quic.InternalError)
)

var quicConfig *quic.Config = &quic.Config{
	EnableDatagrams:                true,
	InitialPacketSize:              1350,
	InitialConnectionReceiveWindow: 5 * 1000 * 1000,
	MaxConnectionReceiveWindow:     100 * 1000 * 1000,
	KeepAlivePeriod:                5 * time.Second,
	MaxIdleTimeout:                 15 * time.Second,
}
