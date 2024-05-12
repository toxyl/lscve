package cves

import (
	"fmt"
	"sort"
	"strings"

	"github.com/toxyl/glog"
	"github.com/toxyl/lscve/utils"
)

type CVE struct {
	ID                 string   `json:"cve_id"`
	Summary            string   `json:"summary"`
	Cvss               float64  `json:"cvss"`
	CvssV2             *float64 `json:"cvss_v2"`
	Epss               float64  `json:"epss"`
	EpssRanking        float64  `json:"ranking_epss"`
	Kev                bool     `json:"kev"`
	ProposeAction      *string  `json:"propose_action"`
	RansomwareCampaign *string  `json:"ransomware_campaign"`
	References         []string `json:"references"`
	Published          string   `json:"published_time"`
	CPEs               []string `json:"cpes,omitempty"`
}

func (cve *CVE) String() string {
	cveParts := strings.Split(cve.ID, "-")
	for i, p := range cveParts {
		cveParts[i] = glog.Auto(p)
	}
	res := glog.PadRight(strings.Join(cveParts, "-"), 16, ' ') + "("
	res += "Severity: " + glog.PadRight(utils.GetSeverity(cve.Cvss)+",", 9, ' ') + " "
	if cve.CvssV2 != nil {
		res += fmt.Sprintf("CVSS: %s, CVSSv2: %s", utils.ColorSeverity(cve.Cvss), utils.ColorSeverity(*cve.CvssV2))
	} else {
		res += fmt.Sprintf("CVSS: %s, CVSSv2: ---", utils.ColorSeverity(cve.Cvss))
	}
	res += fmt.Sprintf(", EPSS: %s, EPSS ranking: %s", utils.ColorEPSS(cve.Epss), utils.ColorEPSS(cve.EpssRanking))
	res += ", " + glog.Auto(cve.Published)
	res += fmt.Sprintf(", CPEs: %3d", len(cve.CPEs))
	res += fmt.Sprintf(", References: %3d", len(cve.References))
	if cve.Kev {
		res += ", " + glog.WrapRed("Known Exploited Vulnerability")
	}
	if cve.RansomwareCampaign != nil {
		res += ", " + glog.WrapOrange("Ransomware Campaign: ") + *cve.RansomwareCampaign
	}
	res += ")"
	return res
}

type CVEs []CVE

func (cves *CVEs) String() string {
	res := ""
	for _, cve := range *cves {
		res += cve.String() + "\n"
	}
	return res
}

func (cves *CVEs) SortByID(desc bool) *CVEs {
	res := *cves
	sort.Slice(res, func(i, j int) bool {
		if desc {
			return res[i].ID > res[j].ID
		}
		return res[i].ID < res[j].ID
	})
	return &res
}

func (cves *CVEs) SortByCVSS(desc bool) *CVEs {
	res := *cves
	sort.Slice(res, func(i, j int) bool {
		if desc {
			return res[i].Cvss > res[j].Cvss
		}
		return res[i].Cvss < res[j].Cvss
	})
	return &res
}

func (cves *CVEs) SortByCVSSV2(desc bool) *CVEs {
	res := *cves
	sort.Slice(res, func(i, j int) bool {
		if desc {
			return *res[i].CvssV2 > *res[j].CvssV2
		}
		return *res[i].CvssV2 < *res[j].CvssV2
	})
	return &res
}

func (cves *CVEs) SortByEPSS(desc bool) *CVEs {
	res := *cves
	sort.Slice(res, func(i, j int) bool {
		if desc {
			return res[i].Epss > res[j].Epss
		}
		return res[i].Epss < res[j].Epss
	})
	return &res
}

func (cves *CVEs) SortByEPSSRanking(desc bool) *CVEs {
	res := *cves
	sort.Slice(res, func(i, j int) bool {
		if desc {
			return res[i].EpssRanking > res[j].EpssRanking
		}
		return res[i].EpssRanking < res[j].EpssRanking
	})
	return &res
}

func (cves *CVEs) SortByPublished(desc bool) *CVEs {
	res := *cves
	sort.Slice(res, func(i, j int) bool {
		if desc {
			return res[i].Published > res[j].Published
		}
		return res[i].Published < res[j].Published
	})
	return &res
}
