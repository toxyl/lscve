# lscve
CLI utility to query Shodan's CVE DB

## Installing
```bash
CGO_ENABLED=0 go build .
cp lscve /usr/local/bin
lscve
```

## Usage
```
lscve searches Shodan's CVE DB.

Usage:    lscve [cve-id]
            lscve newest   [limit] <by [kev|epss]>
            lscve find     [limit]  by [id|cvss|cvssv2|epss|epss-ranking|published]<_asc> where [date|product|cpe23] = [start_date to end_date|product|cpe23]
            lscve find-kev [limit]  by [id|cvss|cvssv2|epss|epss-ranking|published]<_asc> where [date|product|cpe23] = [start_date to end_date|product|cpe23]
Examples: lscve CVE-2016-10087
            lscve newest   10
            lscve newest   10 by kev
            lscve find     10 by cvss              where date    = 2023-01-01 to 2023-12-31
            lscve find     10 by epss              where product = php
            lscve find     10 by epss_asc          where cpe23   = cpe:2.3:a:libpng:libpng:0.8
            lscve find-kev 10 by epss-ranking_asc  where cpe23   = cpe:2.3:a:libpng:libpng:0.8
```

