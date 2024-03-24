package main

import (
	"net"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Channel for queuing IPs for DNS lookup.
	dnsLookupChan = make(chan string, 100)

	// Cache for storing resolved DNS names to minimize lookups.
	dnsCache = make(map[string]string)

	// Mutex for safe access to the DNS cache.
	cacheMutex = sync.Mutex{}
)

func init() {
	// Start the DNS lookup worker on initialization.
	go dnsLookupWorker()
}

// dnsLookupWorker processes IPs from dnsLookupChan and performs DNS lookups.
func dnsLookupWorker() {
	for ip := range dnsLookupChan {
		cacheMutex.Lock()
		// Check cache to avoid redundant lookups.
		if _, found := dnsCache[ip]; !found {
			cacheMutex.Unlock() // Unlock before the potentially slow network call.
			names, err := net.LookupAddr(ip)
			cacheMutex.Lock() // Lock again to update the cache.
			if err == nil && len(names) > 0 {
				dnsName := strings.TrimRight(names[0], ".")
				dnsCache[ip] = dnsName
				dnsNames.With(prometheus.Labels{"ip": ip, "dnsName": dnsName}).Set(1)
			} else {
				// Use the IP itself as a placeholder if the lookup fails.
				dnsCache[ip] = ip
			}
		}
		cacheMutex.Unlock()
	}
}

// queueDNSLookup sends an IP address to dnsLookupChan for DNS resolution.
// It checks the cache first to avoid unnecessary lookups.
func queueDNSLookup(ip string) {
	cacheMutex.Lock()
	_, found := dnsCache[ip]
	cacheMutex.Unlock()
	if !found {
		select {
		case dnsLookupChan <- ip:
			// IP successfully queued for lookup.
		default:
			// Channel is full, proceed without blocking.
		}
	}
}
