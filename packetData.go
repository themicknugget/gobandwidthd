// packetData.go
package main

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketData struct {
	EthLayer      layers.Ethernet
	Ip4Layer      layers.IPv4
	Ip6Layer      layers.IPv6
	TcpLayer      layers.TCP
	UdpLayer      layers.UDP
	Icmp4Layer    layers.ICMPv4
	Icmp6Layer    layers.ICMPv6
	DecodedLayers []gopacket.LayerType
}

var packetDataPool = sync.Pool{
	New: func() interface{} {
		return &PacketData{
			DecodedLayers: make([]gopacket.LayerType, 0, 10),
		}
	},
}
