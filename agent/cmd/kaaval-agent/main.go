package main

import (
	"flag"
	"log"
	"os"
	"time"

	"kaaval/agent/internal/collector"
	"kaaval/agent/internal/transport"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8000", "Kaaval Control Plane URL")
	token := flag.String("token", "", "Enrollment token (Tenant ID)")
	interval := flag.Int("interval", 30, "Heartbeat interval in seconds")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("KAAVAL_TOKEN")
	}
	if *token == "" {
		log.Fatal("Enrollment token required. Set KAAVAL_TOKEN env var or use -token flag.")
	}

	log.Printf("Starting Kaaval Agent — server: %s", *serverURL)

	client := transport.New(*serverURL)

	sysInfo, err := collector.GetSystemInfo()
	if err != nil {
		log.Fatalf("Failed to collect system info: %v", err)
	}

	log.Printf("Host: %s (%s) @ %s", sysInfo.Hostname, sysInfo.OS, sysInfo.IP)
	log.Println("Enrolling...")

	resp, err := client.Post("/api/v1/agents/enroll", map[string]string{
		"enrollment_token": *token,
		"hostname":         sysInfo.Hostname,
		"os_info":          sysInfo.OS,
		"ip_address":       sysInfo.IP,
	})
	if err != nil {
		log.Fatalf("Enrollment failed: %v", err)
	}

	agentID, ok := resp["id"].(string)
	if !ok {
		log.Fatalf("Unexpected enroll response: %v", resp)
	}
	enrollmentKey := resp["enrollment_key"].(string)
	log.Printf("Enrolled — Agent ID: %s", agentID)

	// Collect packages once at startup for CVE correlation
	packages := collector.GetInstalledPackages()
	log.Printf("Collected %d installed packages", len(packages))

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C

		info, _ := collector.GetSystemInfo()

		hb := map[string]interface{}{
			"id":             agentID,
			"enrollment_key": enrollmentKey,
			"hostname":       info.Hostname,
			"ip_address":     info.IP,
			"os_info":        info.OS,
		}
		// Only resend packages on first heartbeat, then every ~10 minutes
		if packages != nil {
			hb["packages"] = packages
			packages = nil // clear after first send; re-scan on next restart
		}

		if _, err := client.Post("/api/v1/agents/heartbeat", hb); err != nil {
			log.Printf("Heartbeat failed: %v", err)
		} else {
			log.Printf("Heartbeat ok — %s", info.IP)
		}
	}
}
