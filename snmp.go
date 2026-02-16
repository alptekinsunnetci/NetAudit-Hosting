package main

import (
	"context"
	"time"

	"github.com/gosnmp/gosnmp"
)

func scanSNMP(ctx context.Context, ip string, timeout time.Duration) ScanResult {
	risk := RiskRegistry[161]
	res := ScanResult{
		IP:          ip,
		Port:        161,
		Service:     risk.Service,
		Severity:    risk.Severity,
		Description: risk.Description,
		Remedy:      risk.Recommendation,
	}

	gs := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   0,
	}

	err := gs.Connect()
	if err != nil {
		return res
	}
	defer gs.Conn.Close()

	_, err = gs.Get([]string{"1.3.6.1.2.1.1.2.0"})
	if err == nil {
		res.IsVuln = true
		res.Description = "SNMP service is accessible with the 'public' community string."
	}

	return res
}
