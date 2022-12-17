package udp

import (
	"net"

	"github.com/lucas-clemente/quic-go"
)

const udpBufferSize = 4096

type ObfsUDPConn struct {
	net.UDPConn
	quic.Obfuscator
}

func NewObfsUDPConn(udpConn *net.UDPConn, obfs quic.Obfuscator) *ObfsUDPConn {
	return &ObfsUDPConn{
		UDPConn:    *udpConn,
		Obfuscator: obfs,
	}
}
