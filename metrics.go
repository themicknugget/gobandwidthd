package main

import (
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metricKey struct {
	iface    string
	ip       string
	srcIP    string
	dstIP    string
	protocol string
}

var (
	packetsPerIP = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bandwidth_packets_total",
		Help: "Total number of packets by IP address and protocol, separated by interface.",
	}, []string{"interface", "ip", "srcip", "dstip", "protocol"})

	bytesPerProtocolPerIP = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bandwidth_bytes_total",
		Help: "Total number of bytes transferred by IP address and protocol, separated by interface.",
	}, []string{"interface", "ip", "srcip", "dstip", "protocol"})

	dnsNames = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bandwidth_dns_names",
		Help: "Gauge metric for IP addresses with DNS name as a label.",
	}, []string{"ip", "dnsName"})
	packetCounterCache sync.Map // Cache for packetsPerIP metrics
	byteCounterCache   sync.Map // Cache for bytesPerProtocolPerIP metrics
)

func updatePacketCounter(iface, metricIP, srcIP, dstIP, protocol string) {
	// Use metricIP in the cache key to differentiate metrics by the actual IP used for metrics.
	key := iface + "|" + metricIP + "|" + srcIP + "|" + dstIP + "|" + protocol

	// Try to load the counter from cache
	if val, ok := packetCounterCache.Load(key); ok {
		val.(prometheus.Counter).Inc()
		return
	}

	// If not found in cache, get or create the counter and store it in the cache
	counter, err := packetsPerIP.GetMetricWith(prometheus.Labels{"interface": iface, "ip": metricIP, "srcip": srcIP, "dstip": dstIP, "protocol": protocol})
	if err != nil {
		log.Printf("Error getting packet metric: %v", err)
		return
	}

	packetCounterCache.Store(key, counter)
	counter.Inc()
}

func updateByteCounter(iface, metricIP, srcIP, dstIP, protocol string, packetSize float64) {
	// Similar adjustment for bytes metric
	key := iface + "|" + metricIP + "|" + srcIP + "|" + dstIP + "|" + protocol

	if val, ok := byteCounterCache.Load(key); ok {
		val.(prometheus.Counter).Add(packetSize)
		return
	}

	counter, err := bytesPerProtocolPerIP.GetMetricWith(prometheus.Labels{"interface": iface, "ip": metricIP, "srcip": srcIP, "dstip": dstIP, "protocol": protocol})
	if err != nil {
		log.Printf("Error getting byte metric: %v", err)
		return
	}

	byteCounterCache.Store(key, counter)
	counter.Add(packetSize)
}
