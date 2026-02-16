package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func scanFTP(ctx context.Context, ip string, timeout time.Duration) ScanResult {
	risk := RiskRegistry[21]
	res := ScanResult{
		IP:          ip,
		Port:        21,
		Service:     risk.Service,
		Severity:    risk.Severity,
		Description: risk.Description,
		Remedy:      risk.Recommendation,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "21"))
	if err != nil {
		return res
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	_, err = reader.ReadString('\n')
	if err != nil {
		return res
	}

	fmt.Fprintf(conn, "USER anonymous\r\n")
	resp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(resp, "331") {
		res.IsVuln = false
		return res
	}

	fmt.Fprintf(conn, "PASS anonymous\r\n")
	resp, err = reader.ReadString('\n')
	if err != nil {
		res.IsVuln = false
		return res
	}

	if strings.HasPrefix(resp, "230") {
		res.IsVuln = true
		res.Severity = SeverityCritical
		res.Description = "FTP servisi ANONİM girişe izin veriyor! Hassas dosyalar sızdırılabilir."

		fmt.Fprintf(conn, "PASV\r\n")
		resp, _ = reader.ReadString('\n')
		if strings.HasPrefix(resp, "227") {
			fmt.Fprintf(conn, "LIST\r\n")
			resp, _ = reader.ReadString('\n')
			if strings.HasPrefix(resp, "150") {
				res.Description += " Dizin listeleme (LIST) başarılı."
			}
		}
	} else {
		res.IsVuln = false
	}

	return res
}
