package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

const WebhookURL = "http://your-monitoring-system.com/webhook" // Webhook URL for monitoring system
var logFile *os.File

// initLog initializes logging system
func initLog() {
	var err error
	logFile, err = os.OpenFile("anomalies.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("⚠️ Cannot open log file: %v", err)
	}
	log.SetOutput(logFile)
}

// logAnomaly logs detected anomalies to both console and log file
func logAnomaly(msg string) {
	fmt.Println(msg)
	log.Println(msg)
	sendWebhookAlert(msg)
}

// checkParentChild analyzes parent-child process relationships
func checkParentChild() {
	procs, _ := process.Processes()
	for _, proc := range procs {
		parentPid, _ := proc.Ppid()
		parent, _ := process.NewProcess(parentPid)
		parentName, _ := parent.Name()
		procName, _ := proc.Name()

		// Alert if the parent-child relation is suspicious
		if parentName == "nginx" && procName == "bash" {
			msg := fmt.Sprintf("⚠️ Suspicious Parent-Child Relation: %s (PID %d) -> %s (PID %d)", parentName, parentPid, procName, proc.Pid)
			logAnomaly(msg)
		}
	}
}

// checkMemoryUsage monitors memory usage of processes
func checkMemoryUsage() {
	procs, _ := process.Processes()
	for _, proc := range procs {
		memInfo, _ := proc.MemoryInfo()
		if memInfo.RSS > 500*1024*1024 { // Alert if memory usage exceeds 500MB
			name, _ := proc.Name()
			msg := fmt.Sprintf("⚠️ High Memory Usage: %s (PID %d) - Memory: %.2fMB", name, proc.Pid, float64(memInfo.RSS)/(1024*1024))
			logAnomaly(msg)
		}
	}
}

// checkCPUUsage monitors CPU usage and logs high consumption
func checkCPUUsage() {
	procs, _ := process.Processes()
	for _, proc := range procs {
		cpuPercent, _ := proc.CPUPercent()
		if cpuPercent > 80.0 { // Alert if CPU usage exceeds 80%
			name, _ := proc.Name()
			msg := fmt.Sprintf("⚠️ High CPU Usage: %s (PID %d) - CPU: %.2f%%", name, proc.Pid, cpuPercent)
			logAnomaly(msg)
		}
	}
}

// checkNetworkConnections inspects open network connections for anomalies
func checkNetworkConnections() {
	connections, _ := net.Connections("inet")
	for _, conn := range connections {
		if conn.Status == "LISTEN" {
			msg := fmt.Sprintf("⚠️ Suspicious Listening Port: PID %d is listening on %s:%d", conn.Pid, conn.Laddr.IP, conn.Laddr.Port)
			logAnomaly(msg)
		}
	}
}

// sendWebhookAlert sends alerts to the monitoring system via webhook
func sendWebhookAlert(msg string) {
	jsonData := []byte(`{"alert": "` + msg + `"}`)
	http.Post(WebhookURL, "application/json", bytes.NewBuffer(jsonData))
}

// terminateProcess kills suspicious processes
func terminateProcess(pid int32) {
	proc, _ := process.NewProcess(pid)
	_ = proc.Kill()
	logAnomaly(fmt.Sprintf("⛔ Terminated suspicious process: %d", pid))
}

func main() {
	initLog()
	defer logFile.Close()

	logAnomaly("🚀 Monitoring started...")

	for {
		checkParentChild()
		checkMemoryUsage()
		checkCPUUsage()
		checkNetworkConnections()
		time.Sleep(10 * time.Second) // Check every 10 seconds
	}
}
