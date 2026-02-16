package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func scanLDAP(ctx context.Context, ip string, timeout time.Duration) ScanResult {
	risk := RiskRegistry[389]
	res := ScanResult{
		IP:          ip,
		Port:        389,
		Service:     risk.Service,
		Severity:    risk.Severity,
		Description: risk.Description,
		Remedy:      risk.Recommendation,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "389"))
	if err != nil {
		return res
	}
	l := ldap.NewConn(conn, false)
	l.Start()
	defer l.Close()

	err = l.UnauthenticatedBind("")
	if err != nil {
		res.IsVuln = true
		return res
	}

	res.Severity = SeverityCritical
	res.Description = "LDAP allows anonymous bind. This can lead to Active Directory enumeration."
	res.IsVuln = true

	searchReq := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"namingContexts", "supportedLDAPVersion"}, nil,
	)
	sr, err := l.Search(searchReq)
	if err == nil && len(sr.Entries) > 0 {
		res.Description += " RootDSE is readable."
		for _, entry := range sr.Entries {
			contexts := entry.GetAttributeValues("namingContexts")
			if len(contexts) > 0 {
				res.Description += fmt.Sprintf(" Found Naming Contexts: %v.", contexts)
			}
		}
	}

	return res
}
