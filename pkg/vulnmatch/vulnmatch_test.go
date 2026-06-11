package vulnmatch

import "testing"

func hasCVE(vulns []Vuln, cve string) bool {
	for _, v := range vulns {
		if v.CVE == cve {
			return true
		}
	}
	return false
}

func TestMatchBannerApacheVulnerable(t *testing.T) {
	v := MatchBanner("Apache/2.4.49 (Unix)")
	if !hasCVE(v, "CVE-2021-41773") {
		t.Fatalf("expected CVE-2021-41773 for Apache 2.4.49, got %+v", v)
	}
}

func TestMatchBannerApachePatched(t *testing.T) {
	v := MatchBanner("Apache/2.4.58 (Unix)")
	if hasCVE(v, "CVE-2021-41773") {
		t.Fatalf("Apache 2.4.58 should not match CVE-2021-41773")
	}
}

func TestMatchVsftpdBackdoor(t *testing.T) {
	v := MatchBanner("vsftpd 2.3.4")
	if !hasCVE(v, "CVE-2011-2523") {
		t.Fatalf("expected vsftpd backdoor, got %+v", v)
	}
	for _, vv := range v {
		if vv.CVE == "CVE-2011-2523" && (!vv.ExploitAvailable || vv.MSFModule == "") {
			t.Errorf("vsftpd backdoor should have an exploit + MSF module")
		}
	}
}

func TestMatchExplicit(t *testing.T) {
	v := Match("nginx", "1.18.0")
	if !hasCVE(v, "CVE-2021-23017") {
		t.Fatalf("expected nginx resolver CVE, got %+v", v)
	}
	if hasCVE(Match("nginx", "1.99"), "CVE-2021-23017") {
		t.Fatal("nginx 1.99 should not match")
	}
}

func TestVersionLE(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.4.49", "2.4.49", true},
		{"2.4.10", "2.4.49", true},
		{"2.4.50", "2.4.49", false},
		{"7.2p2", "7.7", true},
		{"1.20.0", "1.20.0", true},
		{"10.0", "9.0", false},
	}
	for _, c := range cases {
		if got := versionLE(c.a, c.b); got != c.want {
			t.Errorf("versionLE(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
