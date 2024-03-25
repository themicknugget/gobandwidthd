// capture.go
package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var packetDataPool = sync.Pool{
	New: func() interface{} {
		return &PacketData{
			DecodedLayers: make([]gopacket.LayerType, 0, 10),
		}
	},
}
var ipStringCache sync.Map

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

func capturePackets(device string, wg *sync.WaitGroup) {
	defer wg.Done()
	// Create a new InactiveHandle
	inact, err := pcap.NewInactiveHandle(device)
	if err != nil {
		log.Fatalf("Could not create inactive handle: %v", err)
	}
	defer inact.CleanUp()

	// Set the snapshot length to 1600 bytes
	if err := inact.SetSnapLen(1600); err != nil {
		log.Fatalf("Could not set snapshot length: %v", err)
	}

	// Set the interface in promiscuous mode
	if err := inact.SetPromisc(true); err != nil {
		log.Fatalf("Could not set promiscuous mode: %v", err)
	}

	// Set the timeout to block indefinitely
	if err := inact.SetTimeout(pcap.BlockForever); err != nil {
		log.Fatalf("Could not set timeout: %v", err)
	}

	// Set the buffer size (e.g., 10 MiB)
	if err := inact.SetBufferSize(1024 * 1024 * 10); err != nil {
		log.Fatalf("Could not set buffer size: %v", err)
	}

	// Activate the handle
	handle, err := inact.Activate()
	if err != nil {
		log.Fatalf("Could not activate handle: %v", err)
	}
	defer handle.Close()

	// Reuse PacketData and parser for zero-copy packet processing
	packetData := packetDataPool.Get().(*PacketData)
	defer packetDataPool.Put(packetData)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &packetData.EthLayer, &packetData.Ip4Layer, &packetData.Ip6Layer, &packetData.TcpLayer, &packetData.UdpLayer, &packetData.Icmp4Layer, &packetData.Icmp6Layer)

	for {
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Printf("Error reading packet data: %v", err)
			continue
		}
		packetData.DecodedLayers = packetData.DecodedLayers[:0]
		if err := parser.DecodeLayers(data, &packetData.DecodedLayers); err != nil {
			continue
		}

		processPacket(packetData, device)
		time.Sleep(100 * time.Millisecond) // Introduce a small delay to reduce CPU usage
	}
}

func processPacket(packetData *PacketData, iface string) {
	var srcIP, dstIP, protocol string
	var packetSize float64

	for _, layerType := range packetData.DecodedLayers {
		switch layerType {
		case layers.LayerTypeIPv4:
			srcIP = cachedIPString(packetData.Ip4Layer.SrcIP)
			dstIP = cachedIPString(packetData.Ip4Layer.DstIP)
			packetSize = float64(len(packetData.Ip4Layer.Payload))
		case layers.LayerTypeIPv6:
			srcIP = cachedIPString(packetData.Ip6Layer.SrcIP)
			dstIP = cachedIPString(packetData.Ip6Layer.DstIP)
			packetSize = float64(len(packetData.Ip6Layer.Payload))
		case layers.LayerTypeTCP:
			protocol = "tcp"
		case layers.LayerTypeUDP:
			protocol = "udp"
		case layers.LayerTypeICMPv4:
			protocol = "icmpv4"
		case layers.LayerTypeICMPv6:
			protocol = "icmpv6"
		}
	}

	if srcIP == "" || dstIP == "" {
		return
	}

	// Filter out packets where the src or dst IP matches the interface's IPs
	excludedIPsMu.RLock()
	_, srcIPExcluded := excludedIPs[srcIP]
	_, dstIPExcluded := excludedIPs[dstIP]
	excludedIPsMu.RUnlock()
	if srcIPExcluded || dstIPExcluded {
		return // Ignore this packet
	}

	metricIP := checkIPSubnetMembership(srcIP, dstIP)

	updatePacketCounter(iface, metricIP, srcIP, dstIP, protocol)
	updateByteCounter(iface, metricIP, srcIP, dstIP, protocol, packetSize)
}

func cachedIPString(ip net.IP) string {
	// Attempt to retrieve the cached string representation.
	if ipStr, ok := ipStringCache.Load(ip.String()); ok {
		// Update the last update time for the key
		lastAccessMap.Store(ipStr, time.Now())
		return ipStr.(string)
	}

	// Convert to string and cache if not found.
	ipStr := ip.String()
	ipStringCache.Store(ip.String(), ipStr)
	return ipStr
}
