package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	packetsPerIP = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bandwidth_packets_total",
		Help: "Total number of packets by IP address and protocol, separated by interface.",
	}, []string{"interface", "ip", "protocol"})

	bytesPerProtocolPerIP = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bandwidth_bytes_total",
		Help: "Total number of bytes transferred by IP address and protocol, separated by interface.",
	}, []string{"interface", "ip", "protocol"})

	dnsNames = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bandwidth_dns_names",
		Help: "Gauge metric for IP addresses with DNS name as a label.",
	}, []string{"ip", "dnsName"})
)
