// capture.go
package main

import (
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func capturePackets(device string, wg *sync.WaitGroup) {
	defer wg.Done()
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Could not open device %s: %v", device, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		packetData := packetDataPool.Get().(*PacketData)
		packetData.DecodedLayers = packetData.DecodedLayers[:0]

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &packetData.EthLayer, &packetData.Ip4Layer, &packetData.Ip6Layer, &packetData.TcpLayer, &packetData.UdpLayer, &packetData.Icmp4Layer, &packetData.Icmp6Layer)
		err := parser.DecodeLayers(packet.Data(), &packetData.DecodedLayers)
		if err != nil {
			packetDataPool.Put(packetData)
			continue
		}

		processPacket(packetData, device)
		packetDataPool.Put(packetData)
	}
}

func processPacket(packetData *PacketData, iface string) {
	var srcIP, dstIP, protocol string
	var packetSize float64

	for _, layerType := range packetData.DecodedLayers {
		switch layerType {
		case layers.LayerTypeIPv4:
			srcIP = packetData.Ip4Layer.SrcIP.String()
			dstIP = packetData.Ip4Layer.DstIP.String()
			packetSize = float64(len(packetData.Ip4Layer.Payload))
		case layers.LayerTypeIPv6:
			srcIP = packetData.Ip6Layer.SrcIP.String()
			dstIP = packetData.Ip6Layer.DstIP.String()
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

	queueDNSLookup(srcIP)
	queueDNSLookup(dstIP)

	metricIP := checkIPSubnetMembership(srcIP, dstIP)

	updatePacketCounter(iface, metricIP, srcIP, dstIP, protocol)
	updateByteCounter(iface, metricIP, srcIP, dstIP, protocol, packetSize)

	// Additional processing logic remains unchanged...
}
