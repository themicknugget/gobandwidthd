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

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var excludedIPs = make(map[string]struct{})
var excludedIPsMu sync.RWMutex
var subnets []*net.IPNet
var subnetsMu sync.RWMutex

func main() {
	// go adjustGOGCDynamically()

	go func() {
		log.Println("Starting profiling server on http://:6060")
		if err := http.ListenAndServe(":6060", nil); err != nil {
			log.Fatalf("Failed to start profiling server: %v", err)
		}
	}()

	go cleanupStaleMap()

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
				excludedIPs[cachedIPString(v.IP)] = struct{}{}
				fmt.Println("Adding ", cachedIPString(v.IP), " to IP list")
				excludedIPsMu.Unlock()
				subnetsMu.Lock()
				subnets = append(subnets, v)
				fmt.Println("Adding ", v.String, " to subnet list")
				subnetsMu.Unlock()
			case *net.IPAddr:
				excludedIPsMu.Lock()
				excludedIPs[cachedIPString(v.IP)] = struct{}{}
				fmt.Println("Adding ", cachedIPString(v.IP), " to IP list")
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
