package vulnmatch

// signatures is a curated set of high-signal service vulnerabilities. It is not
// exhaustive — it covers widely exploited, version-identifiable services so the
// scanner can prioritize and (optionally) drive Metasploit.
var signatures = []sig{
	{
		product: "apache", maxVuln: "2.4.49",
		cve: "CVE-2021-41773", title: "Apache HTTP Server path traversal / RCE",
		severity: "critical", exploit: true, msfModule: "exploit/multi/http/apache_normalize_path_rce",
	},
	{
		product: "vsftpd", maxVuln: "2.3.4",
		cve: "CVE-2011-2523", title: "vsftpd 2.3.4 backdoor command execution",
		severity: "critical", exploit: true, msfModule: "exploit/unix/ftp/vsftpd_234_backdoor",
	},
	{
		product: "proftpd", maxVuln: "1.3.5",
		cve: "CVE-2015-3306", title: "ProFTPD mod_copy remote command execution",
		severity: "critical", exploit: true, msfModule: "exploit/unix/ftp/proftpd_modcopy_exec",
	},
	{
		product: "openssh", maxVuln: "7.7",
		cve: "CVE-2018-15473", title: "OpenSSH username enumeration",
		severity: "medium", exploit: false,
	},
	{
		product: "nginx", maxVuln: "1.20.0",
		cve: "CVE-2021-23017", title: "nginx DNS resolver off-by-one heap write",
		severity: "high", exploit: false,
	},
	{
		product: "microsoft-iis", maxVuln: "6.0",
		cve: "CVE-2017-7269", title: "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl RCE",
		severity: "critical", exploit: true, msfModule: "exploit/windows/iis/iis_webdav_scstoragepathfromurl",
	},
	{
		product: "samba", maxVuln: "4.5.9",
		cve: "CVE-2017-7494", title: "Samba is_known_pipename() RCE (SambaCry)",
		severity: "critical", exploit: true, msfModule: "exploit/linux/samba/is_known_pipename",
	},
	{
		product: "exim", maxVuln: "4.91",
		cve: "CVE-2019-10149", title: "Exim deliver_message() RCE (The Return of the WIZard)",
		severity: "critical", exploit: true, msfModule: "exploit/linux/smtp/exim4_deliver_message",
	},
	{
		product: "tomcat", maxVuln: "9.0.30",
		cve: "CVE-2020-1938", title: "Apache Tomcat AJP file read/inclusion (Ghostcat)",
		severity: "high", exploit: true, msfModule: "auxiliary/admin/http/tomcat_ghostcat",
	},
	{
		product: "jenkins", maxVuln: "2.137",
		cve: "CVE-2018-1000861", title: "Jenkins remote code execution via Stapler",
		severity: "critical", exploit: true, msfModule: "exploit/multi/http/jenkins_metaprogramming",
	},
	{
		product: "drupal", maxVuln: "7.58",
		cve: "CVE-2018-7600", title: "Drupal Drupalgeddon2 remote code execution",
		severity: "critical", exploit: true, msfModule: "exploit/unix/webapp/drupal_drupalgeddon2",
	},
	{
		product: "phpmyadmin", maxVuln: "4.8.1",
		cve: "CVE-2018-12613", title: "phpMyAdmin local file inclusion",
		severity: "high", exploit: true,
	},
}
