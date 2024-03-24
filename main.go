package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet, device)
	}
}

func main() {
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

func processPacket(packet gopacket.Packet, iface string) {
	var metricIP, srcIP, dstIP, protocol string
	var packetSize float64

	packetSize = float64(len(packet.Data()))

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
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

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = "tcp"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		protocol = "udp"
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		protocol = "icmpv4"
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		protocol = "icmpv6"
	} else {
		protocol = "other"
	}

	queueDNSLookup(srcIP)
	queueDNSLookup(dstIP)

	if checkIPInSubnets(srcIP) {
		metricIP = srcIP
	} else if checkIPInSubnets(dstIP) {
		metricIP = dstIP
	} else {
		fmt.Println("Neither ", srcIP, " or ", dstIP, " are in subnets")
	}
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

// checkIPInSubnets checks if the provided IP address belongs to any of the subnets.
func checkIPInSubnets(ip string) bool {
	subnetsMu.RLock()
	defer subnetsMu.RUnlock()
	for _, subnet := range subnets {
		if subnet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}
