package main

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"
)

func scanSMTP(ctx context.Context, ip string, timeout time.Duration) ScanResult {
	risk := RiskRegistry[25]
	res := ScanResult{
		IP:          ip,
		Port:        25,
		Service:     risk.Service,
		Severity:    risk.Severity,
		Description: risk.Description,
		Remedy:      risk.Recommendation,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "25"))
	if err != nil {
		return res
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return res
	}

	if strings.HasPrefix(banner, "220") {
		res.IsVuln = true
		res.Description = "Open SMTP banner detected: " + strings.TrimSpace(banner)
	}

	return res
}
