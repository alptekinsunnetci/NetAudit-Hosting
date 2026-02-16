package main

type Severity string

const (
	SeverityCritical Severity = "KRITIK"
	SeverityHigh     Severity = "YUKSEK"
	SeverityMedium   Severity = "ORTA"
	SeverityLow      Severity = "DUSUK"
)

type RiskDetail struct {
	Service        string
	Severity       Severity
	Description    string
	AttackScenario string
	Recommendation string
}

var RiskRegistry = map[int]RiskDetail{
	445: {
		Service:        "SMB",
		Severity:       SeverityCritical,
		Description:    "Sunucu Mesaj Bloğu (SMB) protokolü dışa açık durumda.",
		AttackScenario: "Fidye yazılımı (ransomware) yayılımı ve ağ içinde yanal hareket (lateral movement).",
		Recommendation: "Firewall üzerinden public erişimi engelleyin. SMB erişimini sadece güvenilir iç ağlarla sınırlandırın.",
	},
	139: {
		Service:        "NetBIOS",
		Severity:       SeverityCritical,
		Description:    "NetBIOS oturum servisi açık durumda.",
		AttackScenario: "Host hakkında bilgi toplama ve potansiyel zafiyet sömürüsü.",
		Recommendation: "TCP üzerinden NetBIOS'u devre dışı bırakın veya portu ağ sınırında engelleyin.",
	},
	3389: {
		Service:        "RDP",
		Severity:       SeverityHigh,
		Description:    "Uzak Masaüstü Protokolü (RDP) internete açık.",
		AttackScenario: "Yönetici erişimi elde etmek için kaba kuvvet (brute-force) saldırıları.",
		Recommendation: "Public RDP erişimini kapatın. VPN veya MFA destekli RDP Gateway kullanın.",
	},
	5985: {
		Service:        "WinRM (HTTP)",
		Severity:       SeverityCritical,
		Description:    "HTTP üzerinden Windows Uzak Yönetim (WinRM) açık.",
		AttackScenario: "Uzaktan kod çalıştırma ve kimlik bilgisi hırsızlığı.",
		Recommendation: "Public WinRM erişimini kapatın. HTTPS (5986) kullanın ve IP kısıtlaması uygulayın.",
	},
	5986: {
		Service:        "WinRM (HTTPS)",
		Severity:       SeverityCritical,
		Description:    "HTTPS üzerinden Windows Uzak Yönetim (WinRM) açık.",
		AttackScenario: "Şifrelenmiş olsa da uzak yönetim arayüzünün dışa açık olması saldırı yüzeyini artırır.",
		Recommendation: "WinRM erişimini sadece yetkili yönetim IP'leri ile sınırlandırın.",
	},
	22: {
		Service:        "SSH",
		Severity:       SeverityHigh,
		Description:    "SSH yönetim portu dışa açık.",
		AttackScenario: "SSH kaba kuvvet saldırıları veya güncel olmayan SSH sürümlerinin sömürülmesi.",
		Recommendation: "SSH erişimini belirli IP'lerle sınırlandırın. Parola yerine SSH anahtarı kullanın.",
	},
	2375: {
		Service:        "Docker API",
		Severity:       SeverityCritical,
		Description:    "Şifrelenmemiş Docker Uzak API'si kimlik doğrulaması olmadan açık.",
		AttackScenario: "Zararlı konteynerler başlatılarak sunucunun tam kontrolünün ele geçirilmesi.",
		Recommendation: "Docker API'yi internete açmayın. Kullanılması gerekiyorsa TLS ve IP kısıtlaması uygulayın.",
	},
	2379: {
		Service:        "etcd",
		Severity:       SeverityCritical,
		Description:    "Kubernetes tarafından kullanılan etcd anahtar-değer deposu açık.",
		AttackScenario: "Hassas yapılandırmaların ve secret'ların okunması/yazılmasıyla tüm cluster'ın ele geçirilmesi.",
		Recommendation: "etcd erişimini sadece cluster iç ağıyla sınırlandırın.",
	},
	6379: {
		Service:        "Redis",
		Severity:       SeverityCritical,
		Description:    "Redis veritabanı kimlik doğrulaması olmadan açık.",
		AttackScenario: "Veri hırsızlığı, veri bozulması veya potansiyel uzaktan kod çalıştırma.",
		Recommendation: "Redis'i localhost veya iç IP'lere bağlayın ve kimlik doğrulamayı etkinleştirin.",
	},
	27017: {
		Service:        "MongoDB",
		Severity:       SeverityCritical,
		Description:    "MongoDB veritabanı dışa açık.",
		AttackScenario: "Büyük veri sızıntısı veya fidye yazılımı (otomatik veritabanı silme/şifreleme).",
		Recommendation: "Kimlik doğrulamayı etkinleştirin ve port erişimini kısıtlayın.",
	},
	9200: {
		Service:        "Elasticsearch",
		Severity:       SeverityCritical,
		Description:    "Elasticsearch API'si dışa açık.",
		AttackScenario: "İndekslenmiş verilere ve cluster yönetim fonksiyonlarına tam erişim.",
		Recommendation: "Elasticsearch'ü kimlik doğrulaması ile koruyun ve API erişimini kısıtlayın.",
	},
	3306: {
		Service:        "MySQL",
		Severity:       SeverityHigh,
		Description:    "MySQL veritabanı sunucusu dışa açık.",
		AttackScenario: "Kaba kuvvet saldırıları ve yetkisiz veri erişimi.",
		Recommendation: "MySQL erişimini iç IP'lerle sınırlandırın ve güçlü parolalar kullanın.",
	},
	5432: {
		Service:        "PostgreSQL",
		Severity:       SeverityCritical,
		Description:    "PostgreSQL veritabanı sunucusu dışa açık.",
		AttackScenario: "Yetkisiz veritabanı erişimi ve veri sızıntısı.",
		Recommendation: "PostgreSQL erişimini iç IP'lerle sınırlandırın ve güçlü parolalar kullanın.",
	},
	11211: {
		Service:        "Memcached",
		Severity:       SeverityCritical,
		Description:    "Memcached servisi dışa açık.",
		AttackScenario: "Veri hırsızlığı veya yüksek hacimli UDP amplifikasyon (DDoS) saldırıları.",
		Recommendation: "Memcached'i sadece iç arayüzlere bağlayın veya kimlik doğrulama kullanın.",
	},
	5900: {
		Service:        "VNC",
		Severity:       SeverityCritical,
		Description:    "VNC masaüstü paylaşımı açık.",
		AttackScenario: "Masaüstü ortamına görsel erişim ve kullanıcı oturumunun ele geçirilmesi.",
		Recommendation: "VNC için SSH tünelleme veya VPN kullanın. Public erişimden kaçının.",
	},
	// HIGH Severity
	53: {
		Service:        "Recursive DNS",
		Severity:       SeverityCritical,
		Description:    "DNS sunucusu dış alan adları için recursive sorgulara izin veriyor (Açık DNS Resolver).",
		AttackScenario: "DNS amplifikasyon DDoS saldırılarında aracı olarak kullanılması ve ağ kaynaklarının sömürülmesi.",
		Recommendation: "DNS yapılandırmasında yerel olmayan istemciler için recursion'ı kapatın veya sadece güvenilir IP'lere izin verin.",
	},
	25: {
		Service:        "SMTP (Open Relay)",
		Severity:       SeverityHigh,
		Description:    "SMTP sunucusu rastgele kaynaklardan e-posta gönderimine (relay) izin veriyor.",
		AttackScenario: "Spam göndericiler tarafından kullanılması ve IP adresinin kara listeye girmesi.",
		Recommendation: "Sadece kimlik doğrulamalı kullanıcılar veya yerel ağlar için relay izni verin.",
	},
	161: {
		Service:        "Kamuya Açık SNMP",
		Severity:       SeverityHigh,
		Description:    "SNMP servisi varsayılan 'public' topluluk dizesini kullanıyor.",
		AttackScenario: "Ağ donanımı ve sistem durumu hakkında bilgi toplama.",
		Recommendation: "Varsayılan community string'i değiştirin ve SNMP erişimini kısıtlayın.",
	},
	21: {
		Service:        "FTP",
		Severity:       SeverityHigh,
		Description:    "FTP servisi dışa açık veya anonim girişe izin veriyor.",
		AttackScenario: "Anonim erişim ile hassas dosyaların indirilmesi veya trafik dinleme yoluyla kimlik bilgisi hırsızlığı.",
		Recommendation: "Anonim girişi kapatın. SFTP veya FTPS'e geçin ve public erişimi kısıtlayın.",
	},
	873: {
		Service:        "Rsync",
		Severity:       SeverityHigh,
		Description:    "Rsync servisi dışa açık.",
		AttackScenario: "Yetkisiz dosya senkronizasyonu ve veri hırsızlığı.",
		Recommendation: "Rsync'i parolasız bırakmayın veya sadece güvenilir IP'lere açın.",
	},
	2049: {
		Service:        "NFS",
		Severity:       SeverityHigh,
		Description:    "Ağ Dosya Sistemi (NFS) paylaşımları dışarıdan görülebiliyor.",
		AttackScenario: "Yetkisiz dosya sistemi bağlama (mount) ve veri erişimi.",
		Recommendation: "NFS erişimini firewall ile sadece iç istemcilerle sınırlandırın.",
	},
	111: {
		Service:        "RPC / Portmapper",
		Severity:       SeverityHigh,
		Description:    "RPC Portmapper servisi dışa açık.",
		AttackScenario: "Mevcut RPC servislerinin haritalanmasıyla daha fazla bilgi toplama.",
		Recommendation: "RPC portlarını ağ sınırında engelleyin.",
	},
	389: {
		Service:        "LDAP",
		Severity:       SeverityHigh,
		Description:    "LDAP dizin servisi açık.",
		AttackScenario: "Kullanıcılar, gruplar ve ağ yapısı hakkında bilgi sızıntısı.",
		Recommendation: "LDAP'ı iç ağlarla sınırlandırın. LDAPS (TLS) kullanın.",
	},
}
