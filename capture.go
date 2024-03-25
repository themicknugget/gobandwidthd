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
	godpi "github.com/mushorg/go-dpi"
	"github.com/mushorg/go-dpi/types"
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

	// Set the timeout
	if err := inact.SetTimeout(pcap.BlockForever); err != nil {
		log.Fatalf("Could not set timeout: %v", err)
	}

	// Activate the handle
	handle, err := inact.Activate()
	if err != nil {
		log.Fatalf("Could not activate handle: %v", err)
	}
	defer handle.Close()

	// Create a packet source to read packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet, device) // Adjust the processPacket signature accordingly
	}
}

func processPacket(packet gopacket.Packet, iface string) {
	var srcIP, dstIP, protocol string

	packetSize := float64(len(packet.Data()))

	// Handling IPv4
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = cachedIPString(ip.SrcIP)
		dstIP = cachedIPString(ip.DstIP)
	}

	// Handling IPv6
	if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		srcIP = cachedIPString(ip6.SrcIP)
		dstIP = cachedIPString(ip6.DstIP)
	}

	// Handling TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol += "+TCP"
	}

	// Handling UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		protocol += "+UDP"
	}

	// Handling ICMP for IPv4
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		protocol += "+ICMPv4"
	}

	// Handling ICMP for IPv6
	if icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6); icmpv6Layer != nil {
		protocol += "+ICMPv6"
	}

	// Handling ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		protocol = "ARP" // Note: ARP does not operate over IPv6
	}

	// DPI with go-dpi, if applicable
	flow, _ := godpi.GetPacketFlow(packet)
	result := godpi.ClassifyFlow(flow)
	if result.Protocol != types.Unknown {
		if protocol != "" {
			protocol += "+"
		}
		protocol += result.Protocol.String()
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
