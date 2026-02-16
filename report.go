package main

import (
	"fmt"
	"os"
	"time"
)

func generateReport(filename string, subnet string, totalIPs int, results []ScanResult) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	criticalCount := 0
	highCount := 0
	for _, res := range results {
		if res.Severity == SeverityCritical {
			criticalCount++
		} else if res.Severity == SeverityHigh {
			highCount++
		}
	}

	html := `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetAudit-Hosting Güvenlik Raporu</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .card { margin-bottom: 2rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .severity-KRITIK { color: #dc3545; font-weight: bold; }
        .severity-YUKSEK { color: #fd7e14; font-weight: bold; }
        .badge-KRITIK { background-color: #dc3545; }
        .badge-YUKSEK { background-color: #fd7e14; }
        .header-section { background: linear-gradient(135deg, #212529 0%%, #343a40 100%%); color: white; padding: 3rem 0; margin-bottom: 2rem; }
    </style>
</head>
<body>
    <div class="header-section">
        <div class="container text-center">
            <h1 class="display-4">NetAudit-Hosting Güvenlik Raporu</h1>
            <p class="lead">Tarama Tarihi: %s</p>
        </div>
    </div>

    <div class="container">
        <div class="row">
            <div class="col-md-4">
                <div class="card p-3 text-center">
                    <h5>Taranan Subnet</h5>
                    <p class="h4 text-primary">%s</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card p-3 text-center">
                    <h5>Toplam IP</h5>
                    <p class="h4">%d</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card p-3 text-center">
                    <h5>Açık Servis Sayısı</h5>
                    <p class="h4 text-danger">%d</p>
                </div>
            </div>
        </div>

        <div class="card p-4">
            <h4 class="mb-3">Özet</h4>
            <table class="table table-bordered">
                <thead class="table-light">
                    <tr>
                        <th>Seviye</th>
                        <th>Bulgu Sayısı</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="severity-KRITIK">KRİTİK</td>
                        <td>%d</td>
                    </tr>
                    <tr>
                        <td class="severity-YUKSEK">YÜKSEK</td>
                        <td>%d</td>
                    </tr>
                </tbody>
            </table>
        </div>

        %s

        %s
    </div>

    <footer class="text-center py-4 text-muted">
        <p>NetAudit-Hosting Security Scan &copy; %d</p>
    </footer>
</body>
</html>`

	criticalTable := ""
	if criticalCount > 0 {
		criticalTable = `
        <h3 class="text-danger mb-3">Kritik Bulgular</h3>
        <div class="table-responsive card p-3">
            <table class="table table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>IP Adresi</th>
                        <th>Port</th>
                        <th>Servis</th>
                        <th>Açıklama</th>
                        <th>Öneri</th>
                    </tr>
                </thead>
                <tbody>`
		for _, res := range results {
			if res.Severity == SeverityCritical {
				criticalTable += fmt.Sprintf(`
                    <tr>
                        <td><code>%s</code></td>
                        <td><span class="badge bg-dark">%d</span></td>
                        <td><strong>%s</strong></td>
                        <td>%s</td>
                        <td><span class="text-success small">%s</span></td>
                    </tr>`, res.IP, res.Port, res.Service, res.Description, res.Remedy)
			}
		}
		criticalTable += `
                </tbody>
            </table>
        </div>`
	}

	highTable := ""
	if highCount > 0 {
		highTable = `
        <h3 class="text-warning mb-3">İyileştirme Önerileri</h3>
        <div class="table-responsive card p-3">
            <table class="table table-hover">
                <thead class="table-secondary">
                    <tr>
                        <th>IP Adresi</th>
                        <th>Port</th>
                        <th>Servis</th>
                        <th>Açıklama</th>
                        <th>Öneri</th>
                    </tr>
                </thead>
                <tbody>`
		for _, res := range results {
			if res.Severity == SeverityHigh {
				highTable += fmt.Sprintf(`
                    <tr>
                        <td><code>%s</code></td>
                        <td><span class="badge bg-secondary">%d</span></td>
                        <td><strong>%s</strong></td>
                        <td>%s</td>
                        <td><span class="text-dark small">%s</span></td>
                    </tr>`, res.IP, res.Port, res.Service, res.Description, res.Remedy)
			}
		}
		highTable += `
                </tbody>
            </table>
        </div>`
	}

	scanDate := time.Now().Format("02.01.2006 15:04:05")
	fmt.Fprintf(f, html, scanDate, subnet, totalIPs, len(results), criticalCount, highCount, criticalTable, highTable, time.Now().Year())

	return nil
}
