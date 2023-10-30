---
title: Denial of Service in get-ip-range package
date: 2021-02-10
tags:
	- "javascript"
	- "dos"
	- "denial of service"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4304/
cves:
	- "CVE-2021-27191"
---
## Summary
Affected versions of get-ip-range are vulnerable to denial of service in case the ip-range is an untrusted input. An attacker could send a large range of IPs e.g. '192.168.1.1/0' and result in a JavaScript heap out of memory crash.

## Product
get-ip-range before 4.0.0.

## Impact
Crashing a program that passes user input to get-ip-range.

## Steps to reproduce
```
import { getIPRange } from 'get-ip-range';
getIPRange('192.168.1.1/0');
```

### Expected result:
```JavaScript heap out of memory``` crash.

## Remediation
Update get-ip-range dependency to 4.0.0 or above.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://www.twitter.com/ynizry).

## Resources
1. Commit [98ca22b](https://github.com/JoeScho/get-ip-range/commit/98ca22b815c77273cbab259811ab0976118e13b6)
