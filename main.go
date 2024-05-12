package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/toxyl/glog"
	"github.com/toxyl/lscve/cves"
	"github.com/toxyl/lscve/utils"
)

var (
	log = glog.NewLoggerSimple("lscve")
)

func init() {
	glog.LoggerConfig.SplitOnNewLine = true
	glog.LoggerConfig.ShowDateTime = false
	glog.LoggerConfig.ShowRuntimeMilliseconds = false
	glog.LoggerConfig.ShowRuntimeSeconds = false
	glog.LoggerConfig.ShowSubsystem = false
}

func help() {
	exe := filepath.Base(os.Args[0])
	log.BlankAuto(`
%s searches Shodan's CVE DB.

Usage:    %s [cve-id]
          %s %s [limit] <by [kev|epss]>
          %s %s [limit]  by [id|cvss|cvssv2|epss|epss-ranking|published]<_asc> where [date|product|cpe23] = [start_date to end_date|product|cpe23]
          %s %s [limit]  by [id|cvss|cvssv2|epss|epss-ranking|published]<_asc> where [date|product|cpe23] = [start_date to end_date|product|cpe23]
Examples: %s %s
          %s %s %s
          %s %s %s by %s
          %s %s %s by %s where %s = %s to %s
          %s %s %s by %s where %s = %s
          %s %s %s by %s where %s = %s
          %s %s %s by %s where %s = %s
`,
		exe,
		exe,
		exe, "newest  ",
		exe, "find    ",
		exe, "find-kev",
		exe, "CVE-2016-10087",
		exe, "newest  ", "10",
		exe, "newest  ", "10", "kev",
		exe, "find    ", "10", "cvss             ", "date   ", "2023-01-01", "2023-12-31",
		exe, "find    ", "10", "epss             ", "product", "php",
		exe, "find    ", "10", "epss_asc         ", "cpe23  ", "cpe:2.3:a:libpng:libpng:0.8",
		exe, "find-kev", "10", "epss-ranking_asc ", "cpe23  ", "cpe:2.3:a:libpng:libpng:0.8",
	)
}

func die(reason string) {
	log.Error("%s", reason)
	log.Blank("")
	help()
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		help()
		return
	}

	op := os.Args[1]
	if strings.HasPrefix(strings.ToLower(op), "cve") {
		cve := cves.FindCVE(op)
		res := utils.AutoColorList(cve.ID, "-") + "\n"
		if cve.Kev {
			res += "\n" + glog.WrapRed("Known Exploited Vulnerability") + "\n"
		}
		if cve.RansomwareCampaign != nil {
			res += glog.WrapOrange("Ransomware Campaign") + ": " + *cve.RansomwareCampaign + "\n"
		}
		res += "\n"
		res += "Published:    " + glog.Auto(cve.Published) + "\n"
		res += "Severity:     " + utils.GetSeverity(cve.Cvss) + "\n"
		res += "CVSS:         " + utils.ColorSeverity(cve.Cvss) + "\n"
		if cve.CvssV2 != nil {
			res += "CVSSv2:       " + utils.ColorSeverity(*cve.CvssV2) + "\n"
		}
		res += "EPSS:         " + utils.ColorEPSS(cve.Epss) + "\n"
		res += "EPSS ranking: " + utils.ColorEPSS(cve.EpssRanking) + "\n"
		res += "CPEs:         " + glog.Auto(len(cve.CPEs)) + "\n"
		res += "References:   " + glog.Auto(len(cve.References)) + "\n"
		res += "\n"
		if cve.ProposeAction != nil {

			res += glog.Bold() + glog.Underline() + "Proposed Action" + glog.Reset() + "\n"
			res += utils.WordWrap(*cve.ProposeAction, 120, "") + "\n\n"
		}
		res += glog.Bold() + glog.Underline() + "Summary" + glog.Reset() + "\n"
		res += utils.WordWrap(cve.Summary, 120, "") + "\n\n"
		cpes := map[string][]string{}
		products := []string{}

		for _, cpe := range cve.CPEs {
			// cpe:2.3:part:vendor:product:version
			parts := strings.Split(cpe, ":")
			k := strings.Join(parts[0:len(parts)-1], ":")
			v := parts[len(parts)-1]
			if _, ok := cpes[k]; !ok {
				cpes[k] = []string{}
				products = append(products, k)
			}
			cpes[k] = append(cpes[k], v)
		}

		full := len(os.Args) == 3 && strings.ToLower(os.Args[2]) == "full"

		res += glog.Bold() + glog.Underline() + "Affected Products (CPEs)" + glog.Reset() + "\n"
		if !full && len(products) > 10 {
			res += glog.HighlightWarning(fmt.Sprintf("Too many affected products, only showing the first 10.\nUse '%s %s %s' to see all %s products.\n",
				glog.Auto(filepath.Base(os.Args[0])), glog.Auto(op), glog.Auto("full"), glog.Auto(len(products))))
			products = products[0:10]
		}

		for _, product := range products {
			parts := strings.Split(product, ":")
			for i, p := range parts {
				parts[i] = glog.Auto(p)
			}
			versions := cpes[product]
			for i, v := range versions {
				versions[i] = glog.Auto(v)
			}
			res += "- " + strings.Join(parts, ":") + ":\n"
			res += "  " + utils.WordWrap(strings.Join(versions, ", "), 120, "  ") + "\n\n"
		}
		res += "\n"
		res += glog.Bold() + glog.Underline() + "References" + glog.Reset() + "\n"
		refs := cve.References
		if !full && len(refs) > 10 {
			res += glog.HighlightWarning(fmt.Sprintf("Too many references, only showing the first 10.\nUse '%s %s %s' to see all %s references.\n",
				glog.Auto(filepath.Base(os.Args[0])), glog.Auto(op), glog.Auto("full"), glog.Auto(len(cve.References))))
			refs = refs[0:10]
		}
		for _, ref := range refs {
			res += "- " + glog.Auto(strings.ReplaceAll(ref, "%", "%%")) + "\n"
		}
		log.Blank(res)
		return
	}

	if strings.ToLower(op) == "newest" {
		// look up newest CVEs
		switch len(os.Args) {
		case 3:
			// no filter given
			limit := os.Args[2]
			log.Blank(cves.Newest(limit).String())
		case 5:
			// filter given
			limit := os.Args[2]
			if strings.ToLower(os.Args[3]) != "by" {
				die("Syntax error.")
			}
			switch strings.ToLower(os.Args[4]) {
			case "kev":
				// lookup newest by kev
				log.Blank(cves.NewestKEV(limit).String())
			case "epss":
				// lookup newest by epss
				log.Blank(cves.NewestEPSS(limit).String())
			default:
				die(fmt.Sprintf("%s is not a valid sort field.", glog.Auto(os.Args[4])))
			}
		default:
			die("Incorrect number of arguments.")
		}
		return
	}

	searchKEV := false
	if strings.ToLower(op) == "find-kev" {
		op = "find"
		searchKEV = true
	}

	if strings.ToLower(op) == "find" {
		if len(os.Args) >= 9 {
			limit := os.Args[2]
			if strings.ToLower(os.Args[3]) != "by" {
				die("Syntax error.")
			}
			sort := os.Args[4]
			sortDesc := true
			if strings.HasSuffix(sort, "_asc") {
				sortDesc = false
				sort = sort[0 : len(sort)-4]
			}
			if strings.ToLower(os.Args[5]) != "where" || strings.ToLower(os.Args[7]) != "=" || (len(os.Args) > 9 && strings.ToLower(os.Args[9]) != "to") {
				die("Syntax error.")
			}
			var list *cves.CVEs
			switch strings.ToLower(os.Args[6]) {
			case "product":
				list = cves.FindByProduct(os.Args[8], limit, searchKEV)

			case "cpe23":
				list = cves.FindByCPE23(os.Args[8], limit, searchKEV)

			case "date":
				list = cves.FindByDate(os.Args[8], os.Args[10], limit, searchKEV)

			default:
				die("Unknown field")
			}
			switch strings.ToLower(sort) {
			case "id":
				list = list.SortByID(sortDesc)
			case "cvss":
				list = list.SortByCVSS(sortDesc)
			case "cvssv2":
				list = list.SortByCVSSV2(sortDesc)
			case "epss":
				list = list.SortByEPSS(sortDesc)
			case "epss-ranking":
				list = list.SortByEPSSRanking(sortDesc)
			case "published":
				list = list.SortByPublished(sortDesc)
			default:
				die("Unknown sort field")
			}

			log.Blank(list.String())
			return
		}
	}

	log.Warning("Invalid args given.")
	help()
}
