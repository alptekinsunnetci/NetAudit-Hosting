# NetAudit-Hosting

NetAudit-Hosting, Go diliyle geliştirilmiş açık kaynaklı bir güvenlik denetim aracıdır. Bulut sağlayıcıların ve hosting firmalarının kendi IP bloklarını denetlemeleri ve dışa açık kritik servisleri tespit etmeleri için tasarlanmıştır.

⚠️ **SADECE SAVUNMA AMAÇLI GÜVENLİK**
⚠️ **SADECE YETKİLİ KULLANIM İÇİN**

## Yasal Uyarı

Bu araç sadece savunma amaçlı güvenlik denetimleri için geliştirilmiştir. Sadece yetkili olduğunuz IP bloklarında kullanılmalıdır. Bu aracın yanlış kullanımı veya neden olabileceği zararlardan geliştiriciler sorumlu tutulamaz.

## Özellikler

- **Subnet Tarama:** CIDR bloklarını genişletir ve tüm IP'leri tarar.
- **Servise Özel Kontroller:** LDAP, DNS, SMTP ve SNMP için inceleme yapar.
- **Risk Puanlaması:** Bulguları KRİTİK ve YÜKSEK risk kategorilerine ayırır.
- **Eşzamanlı Çalışma:** Goroutine worker pool (varsayılan 200 worker) kullanarak yüksek performans sağlar.
- **HTML Raporlama:** HTML tabanlı modern ve detaylı güvenlik raporları üretir.

## Kurulum

```bash
go build -o netaudit
```

## Kullanım

```bash
./netaudit --subnet=1.2.3.0/24 --workers=200 --timeout=2
```

## Kapsanan Riskler

### KRİTİK
- SMB (445), NetBIOS (139)
- Recursive DNS (53)
- WinRM (5985/5986)
- Docker API (2375), etcd (2379)
- Redis (6379), MongoDB (27017), Elasticsearch (9200)
- PostgreSQL (5432)
- Memcached (11211), VNC (5900)
- FTP (21) - *Sadece anonim girişe izin veriyorsa*

### YÜKSEK
- SMTP Open Relay (25)
- Public SNMP (161)
- Rsync (873), NFS (2049), RPC (111)
- LDAP/LDAPS (389)
- SSH (22), RDP (3389), MySQL (3306)

## Lisans
Açık Kaynak - MIT Lisansı.
