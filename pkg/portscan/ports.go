package portscan

// commonServices maps well-known ports to service names.
var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
	587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
	1080: "socks", 1099: "rmiregistry", 1433: "ms-sql", 1521: "oracle",
	1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
	2181: "zookeeper", 2375: "docker", 2376: "docker-ssl", 3000: "http-alt",
	3306: "mysql", 3389: "ms-wbt-server", 3690: "svn", 4444: "metasploit",
	5000: "http-alt", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
	5900: "vnc", 5984: "couchdb", 6000: "x11", 6379: "redis", 6443: "kube-apiserver",
	7001: "weblogic", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
	8081: "http-alt", 8086: "influxdb", 8088: "http-alt", 8089: "splunkd",
	8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9042: "cassandra",
	9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
	9999: "http-alt", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
	27017: "mongodb", 27018: "mongodb", 50000: "sap",
}

// ServiceName returns the well-known service for a port, or "unknown".
func ServiceName(port int) string {
	if s, ok := commonServices[port]; ok {
		return s
	}
	return "unknown"
}

// topPortsList is the 100 most commonly open TCP ports (nmap-style ordering by
// prevalence).
var topPortsList = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}

// TopPorts returns the n most common ports (n clamped to the table size).
func TopPorts(n int) []int {
	if n <= 0 {
		n = 100
	}
	if n > len(topPortsList) {
		n = len(topPortsList)
	}
	out := make([]int, n)
	copy(out, topPortsList[:n])
	return out
}
