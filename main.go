package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	subnet := flag.String("subnet", "", "Target CIDR (e.g., 1.2.3.0/24)")
	workers := flag.Int("workers", 200, "Number of concurrent workers")
	timeout := flag.Int("timeout", 2, "Timeout in seconds")
	flag.Parse()

	if *subnet == "" {
		fmt.Println("Usage: netaudit --subnet=1.2.3.0/24")
		os.Exit(1)
	}

	fmt.Printf("NetAudit-Hosting başlatılıyor: %s (%d worker)...\n", *subnet, *workers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nDurdurma sinyali alındı, kapatılıyor...")
		cancel()
	}()

	start := time.Now()
	results, err := runScanner(ctx, *subnet, *workers, time.Duration(*timeout)*time.Second)
	if err != nil {
		log.Fatalf("Tarama hatası: %v", err)
	}

	ipList, _ := expandSubnet(*subnet)

	reportFile := "NetAudit-Hosting-Report.html"
	err = generateReport(reportFile, *subnet, len(ipList), results)
	if err != nil {
		log.Fatalf("Rapor oluşturma hatası: %v", err)
	}

	fmt.Printf("\nTarama %v içerisinde tamamlandı.\n", time.Since(start).Round(time.Second))
	fmt.Printf("Rapor kaydedildi: %s\n", reportFile)
}
