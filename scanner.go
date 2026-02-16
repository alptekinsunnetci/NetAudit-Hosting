package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type ScanResult struct {
	IP          string
	Port        int
	Service     string
	Severity    Severity
	Description string
	Remedy      string
	IsVuln      bool
	Error       error
}

type Scanner interface {
	Scan(ctx context.Context, ip string) ScanResult
}

type WorkItem struct {
	IP   string
	Port int
}

func runScanner(ctx context.Context, subnet string, workers int, timeout time.Duration) ([]ScanResult, error) {
	ipList, err := expandSubnet(subnet)
	if err != nil {
		return nil, err
	}

	results := make([]ScanResult, 0)
	workChan := make(chan WorkItem, workers*2)
	resultChan := make(chan ScanResult, workers*2)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workChan {
				select {
				case <-ctx.Done():
					return
				default:
					res := scanService(ctx, item.IP, item.Port, timeout)
					if res.IsVuln {
						resultChan <- res
					}
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		for res := range resultChan {
			results = append(results, res)
		}
		close(done)
	}()

	ports := []int{
		445, 139, 3389, 5985, 5986, 22, 2375, 2379, 6379, 27017, 9200, 3306, 5432, 11211, 5900, // CRITICAL
		53, 25, 161, 21, 873, 2049, 111, 389, // HIGH
	}

	for _, ip := range ipList {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				break
			case workChan <- WorkItem{IP: ip, Port: port}:
			}
		}
	}
	close(workChan)
	wg.Wait()
	close(resultChan)
	<-done

	return results, nil
}

func scanService(ctx context.Context, ip string, port int, timeout time.Duration) ScanResult {
	switch port {
	case 53:
		return scanDNS(ctx, ip, timeout)
	case 25:
		return scanSMTP(ctx, ip, timeout)
	case 389:
		return scanLDAP(ctx, ip, timeout)
	case 161:
		return scanSNMP(ctx, ip, timeout)
	case 21:
		return scanFTP(ctx, ip, timeout)
	default:
		return scanGenericTCP(ctx, ip, port, timeout)
	}
}

func scanGenericTCP(ctx context.Context, ip string, port int, timeout time.Duration) ScanResult {
	risk := RiskRegistry[port]
	res := ScanResult{
		IP:          ip,
		Port:        port,
		Service:     risk.Service,
		Severity:    risk.Severity,
		Description: risk.Description,
		Remedy:      risk.Recommendation,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return res
	}
	defer conn.Close()

	res.IsVuln = true
	return res
}

func expandSubnet(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
