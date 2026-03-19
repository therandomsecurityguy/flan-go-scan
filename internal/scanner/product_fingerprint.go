package scanner

import (
	"encoding/json"
	"strings"
)

func MergeProductFingerprints(groups ...[]ProductFingerprint) []ProductFingerprint {
	found := make(map[string]int)
	var merged []ProductFingerprint
	for _, group := range groups {
		for _, product := range group {
			if product.Name == "" {
				continue
			}
			idx, ok := found[product.Name]
			if ok {
				if productConfidenceRank(product.Confidence) > productConfidenceRank(merged[idx].Confidence) {
					merged[idx].Confidence = product.Confidence
				}
				continue
			}
			found[product.Name] = len(merged)
			merged = append(merged, product)
		}
	}
	return merged
}

func DetectServiceProducts(service, version, banner string, metadata []byte, port int, protocol string) []ProductFingerprint {
	svc := strings.ToLower(service)
	versionLower := strings.ToLower(version)
	bannerLower := strings.ToLower(banner)
	proto := strings.ToLower(protocol)

	var products []ProductFingerprint
	add := func(name, confidence string) {
		products = MergeProductFingerprints(products, []ProductFingerprint{{Name: name, Confidence: confidence}})
	}

	switch {
	case strings.Contains(svc, "postgres"):
		add("PostgreSQL", "high")
	case svc == "mysql":
		add("MySQL", "high")
	case strings.Contains(svc, "mssql") || strings.Contains(svc, "sqlserver"):
		add("MSSQL", "high")
	case strings.Contains(svc, "oracle"):
		add("Oracle", "high")
	case strings.Contains(svc, "mongo"):
		add("MongoDB", "high")
	case svc == "redis":
		add("Redis", "high")
	case strings.Contains(svc, "cassandra"):
		add("Cassandra", "high")
	case strings.Contains(svc, "influx"):
		add("InfluxDB", "high")
	case strings.Contains(svc, "neo4j"):
		add("Neo4j", "high")
	case strings.Contains(svc, "memcached"):
		add("Memcached", "high")
	case strings.Contains(svc, "zookeeper"):
		add("ZooKeeper", "high")
	case strings.Contains(svc, "ldap"):
		add("LDAP", "high")
	case svc == "vnc":
		add("VNC", "high")
	case svc == "smtp":
		add("SMTP", "high")
	case svc == "pop3":
		add("POP3", "high")
	case strings.Contains(svc, "ike") || strings.Contains(svc, "isakmp") || strings.Contains(svc, "ipsec"):
		add("IPsec", "high")
	}

	switch {
	case strings.Contains(bannerLower, "postgresql"):
		add("PostgreSQL", "medium")
	case strings.Contains(bannerLower, "mysql"):
		add("MySQL", "medium")
	case strings.Contains(bannerLower, "microsoft sql server") || strings.Contains(bannerLower, "sql server"):
		add("MSSQL", "medium")
	case strings.Contains(bannerLower, "oracle"):
		add("Oracle", "medium")
	case strings.Contains(bannerLower, "mongodb"):
		add("MongoDB", "medium")
	case strings.Contains(bannerLower, "redis"):
		add("Redis", "medium")
	case strings.Contains(bannerLower, "cassandra"):
		add("Cassandra", "medium")
	case strings.Contains(bannerLower, "influxdb"):
		add("InfluxDB", "medium")
	case strings.Contains(bannerLower, "neo4j"):
		add("Neo4j", "medium")
	case strings.Contains(bannerLower, "memcached"):
		add("Memcached", "medium")
	case strings.Contains(bannerLower, "zookeeper"):
		add("ZooKeeper", "medium")
	case strings.Contains(bannerLower, "ldap"):
		add("LDAP", "medium")
	case strings.HasPrefix(bannerLower, "rfb "):
		add("VNC", "medium")
	case strings.HasPrefix(bannerLower, "220 ") || strings.Contains(bannerLower, "esmtp"):
		if port == 25 || port == 465 || port == 587 {
			add("SMTP", "medium")
		}
	case strings.HasPrefix(bannerLower, "+ok"):
		if port == 110 || port == 995 {
			add("POP3", "medium")
		}
	case strings.Contains(bannerLower, "ikev2") || strings.Contains(bannerLower, "isakmp") || strings.Contains(bannerLower, "ipsec"):
		add("IPsec", "medium")
	}

	switch {
	case strings.Contains(versionLower, "postgres"):
		add("PostgreSQL", "low")
	case strings.Contains(versionLower, "mysql"):
		add("MySQL", "low")
	case strings.Contains(versionLower, "oracle"):
		add("Oracle", "low")
	case strings.Contains(versionLower, "mongo"):
		add("MongoDB", "low")
	case strings.Contains(versionLower, "redis"):
		add("Redis", "low")
	}

	var metaText string
	if len(metadata) > 0 {
		metaText = strings.ToLower(string(metadata))
		switch {
		case strings.Contains(metaText, "postgres"):
			add("PostgreSQL", "medium")
		case strings.Contains(metaText, "mysql"):
			add("MySQL", "medium")
		case strings.Contains(metaText, "mssql") || strings.Contains(metaText, "sqlserver") || strings.Contains(metaText, "sql server"):
			add("MSSQL", "medium")
		case strings.Contains(metaText, "oracle"):
			add("Oracle", "medium")
		case strings.Contains(metaText, "mongo"):
			add("MongoDB", "medium")
		case strings.Contains(metaText, "redis"):
			add("Redis", "medium")
		case strings.Contains(metaText, "cassandra"):
			add("Cassandra", "medium")
		case strings.Contains(metaText, "influx"):
			add("InfluxDB", "medium")
		case strings.Contains(metaText, "neo4j"):
			add("Neo4j", "medium")
		case strings.Contains(metaText, "memcached"):
			add("Memcached", "medium")
		case strings.Contains(metaText, "zookeeper"):
			add("ZooKeeper", "medium")
		case strings.Contains(metaText, "ldap"):
			add("LDAP", "medium")
		case strings.Contains(metaText, "rfb"):
			add("VNC", "medium")
		case strings.Contains(metaText, "esmtp"):
			add("SMTP", "medium")
		case strings.Contains(metaText, "pop3"):
			add("POP3", "medium")
		case strings.Contains(metaText, "ikev2") || strings.Contains(metaText, "isakmp") || strings.Contains(metaText, "ipsec"):
			add("IPsec", "medium")
		}

		var raw map[string]any
		if json.Unmarshal(metadata, &raw) == nil {
			if cpes, ok := raw["cpes"].([]any); ok {
				for _, cpe := range cpes {
					cpeStr, _ := cpe.(string)
					switch {
					case strings.Contains(cpeStr, ":postgresql:"):
						add("PostgreSQL", "high")
					case strings.Contains(cpeStr, ":mysql:"):
						add("MySQL", "high")
					case strings.Contains(cpeStr, ":oracle:"):
						add("Oracle", "high")
					case strings.Contains(cpeStr, ":mongodb:"):
						add("MongoDB", "high")
					case strings.Contains(cpeStr, ":redis:"):
						add("Redis", "high")
					case strings.Contains(cpeStr, ":cassandra:"):
						add("Cassandra", "high")
					case strings.Contains(cpeStr, ":influxdb:"):
						add("InfluxDB", "high")
					case strings.Contains(cpeStr, ":neo4j:"):
						add("Neo4j", "high")
					case strings.Contains(cpeStr, ":memcached:"):
						add("Memcached", "high")
					case strings.Contains(cpeStr, ":zookeeper:"):
						add("ZooKeeper", "high")
					case strings.Contains(cpeStr, ":openldap:") || strings.Contains(cpeStr, ":ldap"):
						add("LDAP", "high")
					case strings.Contains(cpeStr, ":realvnc:") || strings.Contains(cpeStr, ":vnc"):
						add("VNC", "high")
					case strings.Contains(cpeStr, ":postfix:") || strings.Contains(cpeStr, ":exim:") || strings.Contains(cpeStr, ":sendmail:"):
						add("SMTP", "high")
					case strings.Contains(cpeStr, ":dovecot:") || strings.Contains(cpeStr, ":courier:") || strings.Contains(cpeStr, ":pop3"):
						add("POP3", "high")
					}
				}
			}
		}
	}

	if proto == "udp" && (port == 500 || port == 4500) && (strings.Contains(metaText, "ike") || strings.Contains(metaText, "isakmp") || strings.Contains(metaText, "ipsec") || strings.Contains(svc, "ike") || strings.Contains(svc, "isakmp") || strings.Contains(svc, "ipsec")) {
		add("IPsec", "high")
	}

	return products
}
