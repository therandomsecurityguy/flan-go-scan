package scanner

import (
	"encoding/json"
	"strings"
)

type productMatcher struct {
	product  string
	patterns []string
	ports    []int
}

var serviceMatchers = []productMatcher{
	{product: "PostgreSQL", patterns: []string{"postgres"}},
	{product: "MySQL", patterns: []string{"mysql"}},
	{product: "MSSQL", patterns: []string{"mssql", "sqlserver"}},
	{product: "Oracle", patterns: []string{"oracle"}},
	{product: "MongoDB", patterns: []string{"mongo"}},
	{product: "Redis", patterns: []string{"redis"}},
	{product: "Cassandra", patterns: []string{"cassandra"}},
	{product: "InfluxDB", patterns: []string{"influx"}},
	{product: "Neo4j", patterns: []string{"neo4j"}},
	{product: "DB2", patterns: []string{"db2"}},
	{product: "Sybase", patterns: []string{"sybase"}},
	{product: "Firebird", patterns: []string{"firebird"}},
	{product: "Memcached", patterns: []string{"memcached"}},
	{product: "ZooKeeper", patterns: []string{"zookeeper"}},
	{product: "CouchDB", patterns: []string{"couchdb"}},
	{product: "ArangoDB", patterns: []string{"arangodb"}},
	{product: "Milvus", patterns: []string{"milvus"}},
	{product: "ChromaDB", patterns: []string{"chromadb", "chroma"}},
	{product: "Pinecone", patterns: []string{"pinecone"}},
	{product: "LDAP", patterns: []string{"ldap"}},
	{product: "SMB", patterns: []string{"smb"}},
	{product: "VNC", patterns: []string{"vnc"}},
	{product: "SMTP", patterns: []string{"smtp"}},
	{product: "POP3", patterns: []string{"pop3"}},
	{product: "OpenVPN", patterns: []string{"openvpn"}},
	{product: "IPsec", patterns: []string{"ike", "isakmp", "ipsec"}},
}

var bannerMatchers = []productMatcher{
	{product: "PostgreSQL", patterns: []string{"postgresql"}},
	{product: "MySQL", patterns: []string{"mysql"}},
	{product: "MSSQL", patterns: []string{"microsoft sql server"}},
	{product: "Oracle", patterns: []string{"oracle"}},
	{product: "MongoDB", patterns: []string{"mongodb"}},
	{product: "Redis", patterns: []string{"redis"}},
	{product: "Cassandra", patterns: []string{"cassandra"}},
	{product: "InfluxDB", patterns: []string{"influxdb"}},
	{product: "Neo4j", patterns: []string{"neo4j"}},
	{product: "DB2", patterns: []string{"db2"}},
	{product: "Sybase", patterns: []string{"sybase"}},
	{product: "Firebird", patterns: []string{"firebird"}},
	{product: "Memcached", patterns: []string{"memcached"}},
	{product: "ZooKeeper", patterns: []string{"zookeeper"}},
	{product: "CouchDB", patterns: []string{"couchdb"}},
	{product: "ArangoDB", patterns: []string{"arangodb"}},
	{product: "Milvus", patterns: []string{"milvus"}},
	{product: "ChromaDB", patterns: []string{"chromadb", "chroma"}},
	{product: "Pinecone", patterns: []string{"pinecone"}},
	{product: "LDAP", patterns: []string{"ldap"}},
	{product: "SMB", patterns: []string{"smb"}},
	{product: "VNC", patterns: []string{"rfb "}},
	{product: "SMTP", patterns: []string{"220 ", "esmtp"}, ports: []int{25, 465, 587}},
	{product: "POP3", patterns: []string{"+ok"}, ports: []int{110, 995}},
	{product: "OpenVPN", patterns: []string{"openvpn"}},
	{product: "IPsec", patterns: []string{"ikev2", "isakmp", "ipsec"}},
}

var versionMatchers = []productMatcher{
	{product: "PostgreSQL", patterns: []string{"postgres"}},
	{product: "MySQL", patterns: []string{"mysql"}},
	{product: "Oracle", patterns: []string{"oracle"}},
	{product: "MongoDB", patterns: []string{"mongo"}},
	{product: "Redis", patterns: []string{"redis"}},
	{product: "CouchDB", patterns: []string{"couchdb"}},
	{product: "ArangoDB", patterns: []string{"arangodb"}},
	{product: "Milvus", patterns: []string{"milvus"}},
	{product: "ChromaDB", patterns: []string{"chroma"}},
}

var metadataMatchers = []productMatcher{
	{product: "PostgreSQL", patterns: []string{"postgres"}},
	{product: "MySQL", patterns: []string{"mysql"}},
	{product: "MSSQL", patterns: []string{"mssql", "sqlserver", "sql server"}},
	{product: "Oracle", patterns: []string{"oracle"}},
	{product: "MongoDB", patterns: []string{"mongo"}},
	{product: "Redis", patterns: []string{"redis"}},
	{product: "Cassandra", patterns: []string{"cassandra"}},
	{product: "InfluxDB", patterns: []string{"influx"}},
	{product: "Neo4j", patterns: []string{"neo4j"}},
	{product: "DB2", patterns: []string{"db2"}},
	{product: "Sybase", patterns: []string{"sybase"}},
	{product: "Firebird", patterns: []string{"firebird"}},
	{product: "Memcached", patterns: []string{"memcached"}},
	{product: "ZooKeeper", patterns: []string{"zookeeper"}},
	{product: "CouchDB", patterns: []string{"couchdb"}},
	{product: "ArangoDB", patterns: []string{"arangodb"}},
	{product: "Milvus", patterns: []string{"milvus"}},
	{product: "ChromaDB", patterns: []string{"chromadb", "chroma"}},
	{product: "Pinecone", patterns: []string{"pinecone"}},
	{product: "LDAP", patterns: []string{"ldap"}},
	{product: "SMB", patterns: []string{"smb"}},
	{product: "VNC", patterns: []string{"rfb"}},
	{product: "SMTP", patterns: []string{"esmtp"}},
	{product: "POP3", patterns: []string{"pop3"}},
	{product: "OpenVPN", patterns: []string{"openvpn"}},
	{product: "IPsec", patterns: []string{"ikev2", "isakmp", "ipsec"}},
}

var cpeMatchers = []productMatcher{
	{product: "PostgreSQL", patterns: []string{":postgresql:"}},
	{product: "MySQL", patterns: []string{":mysql:"}},
	{product: "Oracle", patterns: []string{":oracle:"}},
	{product: "MongoDB", patterns: []string{":mongodb:"}},
	{product: "Redis", patterns: []string{":redis:"}},
	{product: "Cassandra", patterns: []string{":cassandra:"}},
	{product: "InfluxDB", patterns: []string{":influxdb:"}},
	{product: "Neo4j", patterns: []string{":neo4j:"}},
	{product: "DB2", patterns: []string{":db2:"}},
	{product: "Sybase", patterns: []string{":sybase:"}},
	{product: "Firebird", patterns: []string{":firebird:"}},
	{product: "Memcached", patterns: []string{":memcached:"}},
	{product: "ZooKeeper", patterns: []string{":zookeeper:"}},
	{product: "CouchDB", patterns: []string{":couchdb:"}},
	{product: "ArangoDB", patterns: []string{":arangodb:"}},
	{product: "Milvus", patterns: []string{":milvus:"}},
	{product: "ChromaDB", patterns: []string{":chromadb:", ":chroma:"}},
	{product: "Pinecone", patterns: []string{":pinecone:"}},
	{product: "LDAP", patterns: []string{":openldap:", ":ldap"}},
	{product: "SMB", patterns: []string{":samba:", ":smb"}},
	{product: "VNC", patterns: []string{":realvnc:", ":vnc"}},
	{product: "SMTP", patterns: []string{":postfix:", ":exim:", ":sendmail:"}},
	{product: "POP3", patterns: []string{":dovecot:", ":courier:", ":pop3"}},
	{product: "OpenVPN", patterns: []string{":openvpn:"}},
}

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
	metaText := strings.ToLower(string(metadata))

	var products []ProductFingerprint
	add := func(name, confidence string) {
		products = MergeProductFingerprints(products, []ProductFingerprint{{Name: name, Confidence: confidence}})
	}

	applyProductMatchers(svc, port, serviceMatchers, "high", add)
	applyProductMatchers(bannerLower, port, bannerMatchers, "medium", add)
	applyProductMatchers(versionLower, port, versionMatchers, "low", add)
	applyProductMatchers(metaText, port, metadataMatchers, "medium", add)

	if len(metadata) > 0 {
		var raw map[string]any
		if json.Unmarshal(metadata, &raw) == nil {
			if cpes, ok := raw["cpes"].([]any); ok {
				for _, cpe := range cpes {
					cpeStr, _ := cpe.(string)
					applyProductMatchers(strings.ToLower(cpeStr), port, cpeMatchers, "high", add)
				}
			}
		}
	}

	if proto == "udp" && port == 1194 && (containsAny(metaText, []string{"openvpn"}) || containsAny(svc, []string{"openvpn"})) {
		add("OpenVPN", "high")
	}
	if proto == "udp" && (port == 500 || port == 4500) && (containsAny(metaText, []string{"ike", "isakmp", "ipsec"}) || containsAny(svc, []string{"ike", "isakmp", "ipsec"})) {
		add("IPsec", "high")
	}

	return products
}

func applyProductMatchers(text string, port int, matchers []productMatcher, confidence string, add func(string, string)) {
	if text == "" {
		return
	}
	for _, matcher := range matchers {
		if len(matcher.ports) > 0 && !portAllowed(port, matcher.ports) {
			continue
		}
		if containsAny(text, matcher.patterns) {
			add(matcher.product, confidence)
		}
	}
}

func containsAny(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func portAllowed(port int, ports []int) bool {
	for _, allowed := range ports {
		if port == allowed {
			return true
		}
	}
	return false
}
