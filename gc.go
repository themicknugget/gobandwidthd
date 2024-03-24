package main

import (
	"log"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/shirou/gopsutil/mem"
)

func adjustGOGCDynamically() {
	for {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		// Get total allocated heap objects in bytes.
		totalAlloc := float64(memStats.Alloc)

		// Use gopsutil to get available system memory.
		v, err := mem.VirtualMemory()
		if err != nil {
			log.Printf("Error retrieving system memory info: %v", err)
			continue
		}

		usedMemoryMB := totalAlloc / (1024 * 1024)

		// Calculate the percentage of used memory relative to total available memory.
		// Note: v.Available is the available memory for the system, and v.Total is the total system memory.
		// Adding totalAlloc to v.Available since we're interested in the memory headroom including our program's usage.
		usedMemoryPercent := (totalAlloc / float64(v.Available+uint64(totalAlloc))) * 100

		// Check if we're using less than 10% of the available memory.
		if usedMemoryPercent < 10 {
			debug.SetGCPercent(1000) // Make GC less aggressive.
		} else {
			debug.SetGCPercent(100) // Set GC back to default if not within the desired range.
		}

		log.Printf("Current memory usage: %.2f%% (%.2fMB), GOGC set to: %d", usedMemoryPercent, usedMemoryMB, debug.SetGCPercent(-1))

		time.Sleep(30 * time.Second) // Adjust as necessary.
	}
}
