package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // Import for side-effect of registering pprof handlers
	"os"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var excludedIPs = make(map[string]struct{})
var excludedIPsMu sync.RWMutex
var subnets []*net.IPNet
var subnetsMu sync.RWMutex

func capturePackets(device string, wg *sync.WaitGroup) {
	defer wg.Done()
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Could not open device %s: %v", device, err)
	}
	defer handle.Close()

	var ethLayer layers.Ethernet
	var ip4Layer layers.IPv4
	var ip6Layer layers.IPv6
	var tcpLayer layers.TCP
	var udpLayer layers.UDP
	var icmp4Layer layers.ICMPv4
	var icmp6Layer layers.ICMPv6

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ip4Layer, &ip6Layer, &tcpLayer, &udpLayer, &icmp4Layer, &icmp6Layer)
	decodedLayers := make([]gopacket.LayerType, 0, 10)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	for packet := range packetSource.Packets() {
		err := parser.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			log.Printf("Error decoding packet: %v", err)
			continue
		}

		processPacket(decodedLayers, &ethLayer, &ip4Layer, &ip6Layer, &tcpLayer, &udpLayer, &icmp4Layer, &icmp6Layer, device)
	}
}

func main() {
	go func() {
		log.Println("Starting profiling server on http://:6060")
		if err := http.ListenAndServe(":6060", nil); err != nil {
			log.Fatalf("Failed to start profiling server: %v", err)
		}
	}()

	interfaces := os.Getenv("INTERFACES")
	if interfaces == "" {
		interfaces = "eth0"
	}

	var wg sync.WaitGroup
	for _, iface := range strings.Split(interfaces, ",") {
		iface = strings.TrimSpace(iface)
		getNetworkDetails(iface) // Discover and store IPs for the interface
		wg.Add(1)
		go func(i string) {
			defer wg.Done()
			capturePackets(i, &wg) // Adjusted to pass WaitGroup correctly
		}(iface)
	}

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Fatal(http.ListenAndServe(":9090", nil))
	}()

	wg.Wait() // Wait for all packet capture goroutines to complete
}

func processPacket(decodedLayers []gopacket.LayerType, eth *layers.Ethernet, ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP, udp *layers.UDP, icmp4 *layers.ICMPv4, icmp6 *layers.ICMPv6, iface string) {
	var srcIP, dstIP, protocol string
	var packetSize float64

	for _, layerType := range decodedLayers {
		switch layerType {
		case layers.LayerTypeIPv4:
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()
			packetSize = float64(len(ip4.Payload))
		case layers.LayerTypeIPv6:
			srcIP = ip6.SrcIP.String()
			dstIP = ip6.DstIP.String()
			packetSize = float64(len(ip6.Payload))
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
	packetsPerIP.With(prometheus.Labels{"interface": iface, "ip": metricIP, "srcip": srcIP, "dstip": dstIP, "protocol": protocol}).Inc()
	bytesPerProtocolPerIP.With(prometheus.Labels{"interface": iface, "ip": metricIP, "srcip": srcIP, "dstip": dstIP, "protocol": protocol}).Add(packetSize)
}

// getNetworkDetails collects an interface's IP addresses and subnets.
func getNetworkDetails(interfaceName string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting interfaces:", err)
		return
	}

	for _, iface := range interfaces {
		if iface.Name != interfaceName {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("Error getting addresses for interface", iface.Name, ":", err)
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				excludedIPsMu.Lock()
				excludedIPs[v.IP.String()] = struct{}{}
				fmt.Println("Adding ", v.IP.String, " to IP list")
				excludedIPsMu.Unlock()
				subnetsMu.Lock()
				subnets = append(subnets, v)
				fmt.Println("Adding ", v.String, " to subnet list")
				subnetsMu.Unlock()
			case *net.IPAddr:
				excludedIPsMu.Lock()
				excludedIPs[v.IP.String()] = struct{}{}
				fmt.Println("Adding ", v.IP.String, " to IP list")
				excludedIPsMu.Unlock()
			}
		}
	}

	return
}

// checkIPSubnetMembership checks if either the source or destination IP address belongs to any of the subnets.
// It returns the IP that belongs to a subnet, or an empty string if neither do.
func checkIPSubnetMembership(srcIP, dstIP string) string {
	subnetsMu.RLock()
	defer subnetsMu.RUnlock()

	srcParsedIP := net.ParseIP(srcIP)
	dstParsedIP := net.ParseIP(dstIP)

	for _, subnet := range subnets {
		if subnet.Contains(srcParsedIP) {
			return srcIP
		}
		if subnet.Contains(dstParsedIP) {
			return dstIP
		}
	}
	return ""
}
