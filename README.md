# lscve
CLI utility to query Shodan's [CVE DB](https://cvedb.shodan.io/).

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
          lscve newest    [limit] <by [kev|epss]>
          lscve find      [limit]  by [id|cvss|cvssv2|epss|epss-ranking|published]<_asc> where [date|product|cpe23] = [start_date to end_date|product|cpe23]
          lscve find-kev  [limit]  by [id|cvss|cvssv2|epss|epss-ranking|published]<_asc> where [date|product|cpe23] = [start_date to end_date|product|cpe23]
          lscve find-epss [limit]  by [id|cvss|cvssv2|epss|epss-ranking|published]<_asc> where [date|product|cpe23] = [start_date to end_date|product|cpe23]
Examples: lscve CVE-2016-10087
          lscve newest    10
          lscve newest    10 by kev
          lscve find      10 by cvss              where date    = 2023-01-01 to 2023-12-31
          lscve find      10 by epss              where product = php
          lscve find      10 by epss_asc          where cpe23   = cpe:2.3:a:libpng:libpng:0.8
          lscve find-kev  10 by epss-ranking_asc  where cpe23   = cpe:2.3:a:libpng:libpng:0.8
          lscve find-epss 10 by epss-ranking_asc  where cpe23   = cpe:2.3:a:libpng:libpng:0.8

```

## Examples
### Get The 10 Newest CVEs Known To Be Exploited
```bash
$ lscve newest 10 by kev
```
```
    CVE-2024-20353  (Severity: high,     CVSS: 8.6, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.72, 2024-04-24T19:15:46, CPEs:   0, References:   1, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-20359  (Severity: medium,   CVSS: 6.0, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.71, 2024-04-24T19:15:46, CPEs:   0, References:   1, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-4040   (Severity: CRITICAL, CVSS: 10.0, CVSSv2: ---, EPSS: 0.96, EPSS ranking: 0.99, 2024-04-22T20:15:07, CPEs:   0, References:   7, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-3400   (Severity: CRITICAL, CVSS: 10.0, CVSSv2: ---, EPSS: 0.95, EPSS ranking: 0.99, 2024-04-12T08:15:06, CPEs:   0, References:   4, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-29988  (Severity: high,     CVSS: 8.8, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.75, 2024-04-09T17:16:01, CPEs:   0, References:   1, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-29745  (Severity: medium,   CVSS: 5.5, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.74, 2024-04-05T20:15:08, CPEs:   0, References:   1, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-29748  (Severity: high,     CVSS: 7.8, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.51, 2024-04-05T20:15:08, CPEs:   0, References:   1, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-3272   (Severity: CRITICAL, CVSS: 9.8, CVSSv2: 10.0, EPSS: 0.01, EPSS ranking: 0.86, 2024-04-04T01:15:50, CPEs:   0, References:   4, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-3273   (Severity: CRITICAL, CVSS: 9.8, CVSSv2: 7.5, EPSS: 0.83, EPSS ranking: 0.98, 2024-04-04T01:15:50, CPEs:   0, References:   5, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2023-48788  (Severity: CRITICAL, CVSS: 9.8, CVSSv2: ---, EPSS: 0.56, EPSS ranking: 0.98, 2024-03-12T15:15:46, CPEs:   0, References:   1, Known Exploited Vulnerability, Ransomware Campaign: Known)
```
  
### Find Last 10 Python CVEs Sorted By CVSS (Desc)
```bash
$ lscve find 10 by cvss where product = python
``` 
``` 
    CVE-2022-48565  (Severity: CRITICAL, CVSS: 9.8, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.47, 2023-08-22T19:16:32, CPEs:   0, References:   7)
    CVE-2023-41105  (Severity: high,     CVSS: 7.5, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.22, 2023-08-23T07:15:08, CPEs:   0, References:   6)
    CVE-2022-48560  (Severity: high,     CVSS: 7.5, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.26, 2023-08-22T19:16:31, CPEs:   0, References:   6)
    CVE-2023-36632  (Severity: high,     CVSS: 7.5, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.19, 2023-06-25T18:15:09, CPEs:   0, References:   4)
    CVE-2022-48564  (Severity: medium,   CVSS: 6.5, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.23, 2023-08-22T19:16:31, CPEs:   0, References:   3)
    CVE-2022-48566  (Severity: medium,   CVSS: 5.9, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.23, 2023-08-22T19:16:32, CPEs:   0, References:   4)
    CVE-2023-33595  (Severity: medium,   CVSS: 5.5, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.12, 2023-06-07T20:15:09, CPEs:   0, References:   2)
    CVE-2023-40217  (Severity: medium,   CVSS: 5.3, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.17, 2023-08-25T01:15:09, CPEs:   0, References:   5)
    CVE-2023-38898  (Severity: medium,   CVSS: 5.3, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.16, 2023-08-15T17:15:12, CPEs:   0, References:   1)
    CVE-2023-6507   (Severity: medium,   CVSS: 4.9, CVSSv2: ---, EPSS: 0.00, EPSS ranking: 0.25, 2023-12-08T19:15:08, CPEs:   0, References:   5)
```

### Find Top 10 CVEs By EPSS In January 2024 Sorted By CVSS (Asc)
```bash
$ lscve find-epss 10 by cvss_asc where date = 2024-01-01 to 2024-01-31
```
```
    CVE-2023-7028   (Severity: high,     CVSS: 7.5, CVSSv2: ---, EPSS: 0.95, EPSS ranking: 0.99, 2024-01-12T14:15:49, CPEs:   0, References:   3, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2023-6567   (Severity: high,     CVSS: 7.5, CVSSv2: ---, EPSS: 0.20, EPSS ranking: 0.96, 2024-01-11T09:15:49, CPEs:   0, References:   2)
    CVE-2023-46805  (Severity: high,     CVSS: 8.2, CVSSv2: ---, EPSS: 0.97, EPSS ranking: 1.00, 2024-01-12T17:15:09, CPEs:   0, References:   2, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-21893  (Severity: high,     CVSS: 8.2, CVSSv2: ---, EPSS: 0.96, EPSS ranking: 1.00, 2024-01-31T18:15:47, CPEs:   0, References:   1, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-21887  (Severity: CRITICAL, CVSS: 9.1, CVSSv2: ---, EPSS: 0.97, EPSS ranking: 1.00, 2024-01-12T17:15:10, CPEs:   0, References:   2, Known Exploited Vulnerability, Ransomware Campaign: Unknown)
    CVE-2024-23897  (Severity: CRITICAL, CVSS: 9.8, CVSSv2: ---, EPSS: 0.96, EPSS ranking: 0.99, 2024-01-24T18:15:09, CPEs:   0, References:   4)
    CVE-2024-0204   (Severity: CRITICAL, CVSS: 9.8, CVSSv2: ---, EPSS: 0.50, EPSS ranking: 0.98, 2024-01-22T18:15:20, CPEs:   0, References:   4)
    CVE-2023-6634   (Severity: CRITICAL, CVSS: 9.8, CVSSv2: ---, EPSS: 0.20, EPSS ranking: 0.96, 2024-01-11T09:15:50, CPEs:   0, References:   2)
    CVE-2023-51972  (Severity: CRITICAL, CVSS: 9.8, CVSSv2: ---, EPSS: 0.16, EPSS ranking: 0.96, 2024-01-10T13:15:48, CPEs:   0, References:   1)
    CVE-2023-22527  (Severity: CRITICAL, CVSS: 10.0, CVSSv2: ---, EPSS: 0.97, EPSS ranking: 1.00, 2024-01-16T05:15:08, CPEs:   0, References:   3, Known Exploited Vulnerability, Ransomware Campaign: Known)
```

### Get CVE Details
```bash
$ lscve CVE-2023-48788
```
```
    CVE-2023-48788

    Known Exploited Vulnerability
    Ransomware Campaign: Known

    Published:    2024-03-12T15:15:46
    Severity:     CRITICAL
    CVSS:         9.8
    EPSS:         0.56
    EPSS ranking: 0.98
    CPEs:         12
    References:   1

    Proposed Action
    Fortinet FortiClient EMS contains a SQL injection vulnerability that allows an unauthenticated attacker to execute
    commands as SYSTEM via specifically crafted requests.

    Summary
    A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiClientEMS
    version 7.2.0 through 7.2.2, FortiClientEMS 7.0.1 through 7.0.10 allows attacker to execute unauthorized code or
    commands via specially crafted packets.

    Affected Products (CPEs)
    - cpe:2.3:a:fortinet:forticlient_enterprise_management_server:
      7.0.1, 7.0.10, 7.0.2, 7.0.3, 7.0.4, 7.0.6, 7.0.7, 7.0.8, 7.0.9, 7.2.0, 7.2.1, 7.2.2


    References
    - https://fortiguard.com/psirt/FG-IR-24-007
```
