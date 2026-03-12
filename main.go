// KaliWall - Linux Firewall Management Daemon
// Main entry point: initializes firewall engine, logger, REST API, and web UI server.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"kaliwall/internal/analytics"
	"kaliwall/internal/api"
	"kaliwall/internal/firewall"
	"kaliwall/internal/logger"
	"kaliwall/internal/netmon"
	"kaliwall/internal/threatintel"
)

const (
	listenAddr = ":8080"
	logDir     = "logs"
	logFile    = "logs/kaliwall.log"
)

func main() {
	fmt.Println("===================================")
	fmt.Println("  KaliWall - Linux Firewall Daemon")
	fmt.Println("===================================")

	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0750); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	// Initialize traffic logger
	trafficLogger, err := logger.New(logFile)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer trafficLogger.Close()

	// Initialize firewall engine (nftables/iptables)
	fw := firewall.New(trafficLogger)

	// Initialize threat intelligence service (VirusTotal)
	ti := threatintel.New()

	// Start real-time network monitor
	monitor := netmon.New(trafficLogger)
	monitor.Start()

	// Start analytics engine (bandwidth sampling)
	analyticsService := analytics.New(trafficLogger)
	analyticsService.Start()

	// Initialize REST API and web server
	handler := api.NewRouter(fw, trafficLogger, ti, analyticsService)

	// Graceful shutdown on SIGINT/SIGTERM
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("\n[+] KaliWall web UI:  http://localhost%s\n", listenAddr)
		fmt.Printf("[+] REST API base:   http://localhost%s/api/v1\n", listenAddr)
		fmt.Println("[+] Press Ctrl+C to stop the daemon.\n")

		if err := http.ListenAndServe(listenAddr, handler); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	<-stop
	fmt.Println("\n[*] Shutting down KaliWall daemon...")
	monitor.Stop()
	analyticsService.Stop()
	trafficLogger.Log("SYSTEM", "-", "-", "-", "Daemon stopped")
}
