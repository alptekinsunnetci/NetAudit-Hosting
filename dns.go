package main

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

func scanDNS(ctx context.Context, ip string, timeout time.Duration) ScanResult {
	risk := RiskRegistry[53]
	res := ScanResult{
		IP:          ip,
		Port:        53,
		Service:     risk.Service,
		Severity:    risk.Severity,
		Description: risk.Description,
		Remedy:      risk.Recommendation,
	}

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("google.com."), dns.TypeA)
	m.RecursionDesired = true

	addr := net.JoinHostPort(ip, "53")
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		c.Net = "tcp"
		r, _, err = c.Exchange(m, addr)
		if err != nil {
			return res
		}
	}

	if r.RecursionAvailable {
		res.IsVuln = true
		res.Description = "DNS server is open and allows recursive queries for external domains."
	}

	return res
}
