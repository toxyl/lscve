package cves

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/toxyl/lscve/utils"
)

const (
	BASE_URL = "https://cvedb.shodan.io/"
)

type CPEs []string

func (cpes *CPEs) String() string {
	res := ""
	for _, cpe := range *cpes {
		res += utils.AutoColorList(cpe, ":") + "\n"
	}
	return res
}

type urlArg [2]string

func makeURL(endpoint string, args ...urlArg) string {
	res := BASE_URL + endpoint
	if len(args) > 0 {
		res += "?"
		resArgs := []string{}
		for _, a := range args {
			resArgs = append(resArgs, fmt.Sprintf("%s=%s", a[0], a[1]))
		}
		res += strings.Join(resArgs, "&")
	}
	return res
}

func getListFromURL(url string) *CVEs {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching data:", err)
		return nil
	}
	defer resp.Body.Close()

	var found struct{ CVEs CVEs }
	err = json.NewDecoder(resp.Body).Decode(&found)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return nil
	}

	return &found.CVEs
}

func getCPEListFromURL(url string) *CPEs {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching data:", err)
		return nil
	}
	defer resp.Body.Close()

	var found struct{ CPEs CPEs }
	err = json.NewDecoder(resp.Body).Decode(&found)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return nil
	}

	return &found.CPEs
}

func getFromURL(url string) *CVE {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching data:", err)
		return nil
	}
	defer resp.Body.Close()

	var foundCVE CVE
	err = json.NewDecoder(resp.Body).Decode(&foundCVE)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return nil
	}

	return &foundCVE
}

func FindCVE(cve string) *CVE { return getFromURL(makeURL(fmt.Sprintf("cve/%s", cve))) }

func FindByProduct(product, limit string, searchKEV, sortByEPSS bool) *CVEs {
	args := []urlArg{{"product", product}}
	if searchKEV {
		args = append(args, urlArg{"is_kev", "true"})
	}
	if sortByEPSS {
		args = append(args, urlArg{"sort_by_epss", "true"})
	}
	if limit != "0" {
		args = append(args, urlArg{"skip", "0"}, urlArg{"limit", limit})
	}
	return getListFromURL(makeURL("cves", args...))
}

func FindByDate(start, end, limit string, searchKEV, sortByEPSS bool) *CVEs {
	args := []urlArg{{"start_date", start}, {"end_date", end}}
	if searchKEV {
		args = append(args, urlArg{"is_kev", "true"})
	}
	if sortByEPSS {
		args = append(args, urlArg{"sort_by_epss", "true"})
	}
	if limit != "0" {
		args = append(args, urlArg{"skip", "0"}, urlArg{"limit", limit})
	}
	return getListFromURL(makeURL("cves", args...))
}

func FindByCPE23(cpe23, limit string, searchKEV, sortByEPSS bool) *CVEs {
	args := []urlArg{{"cpe23", cpe23}}
	if searchKEV {
		args = append(args, urlArg{"is_kev", "true"})
	}
	if sortByEPSS {
		args = append(args, urlArg{"sort_by_epss", "true"})
	}
	if limit != "0" {
		args = append(args, urlArg{"skip", "0"}, urlArg{"limit", limit})
	}
	return getListFromURL(makeURL("cves", args...))
}

func ProductCPEs(product, limit string) *CPEs {
	args := []urlArg{{"product", product}}
	if limit != "0" {
		args = append(args, urlArg{"skip", "0"}, urlArg{"limit", limit})
	}

	return getCPEListFromURL(makeURL("cpes", args...))
}

func Newest(limit string) *CVEs {
	args := []urlArg{}
	if limit != "0" {
		args = append(args, urlArg{"skip", "0"}, urlArg{"limit", limit})
	}
	return getListFromURL(makeURL("cves", args...))
}

func NewestKEV(limit string) *CVEs {
	args := []urlArg{{"is_kev", "true"}}
	if limit != "0" {
		args = append(args, urlArg{"skip", "0"}, urlArg{"limit", limit})
	}
	return getListFromURL(makeURL("cves", args...))
}

func NewestEPSS(limit string) *CVEs {
	args := []urlArg{{"sort_by_epss", "true"}}
	if limit != "0" {
		args = append(args, urlArg{"skip", "0"}, urlArg{"limit", limit})
	}
	return getListFromURL(makeURL("cves", args...))
}
