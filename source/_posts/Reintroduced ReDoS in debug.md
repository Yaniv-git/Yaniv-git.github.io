---
title: Reintroduced ReDoS in debug
date: 2020-11-18
tags:
	- "javascript"
	- "redos"
	- "npm"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4307/
cves:
---
## Summary
The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the `o` formatter. It takes around 50k characters to block for 2 seconds making this a low severity issue. This vulnerability is a reintroduction of CVE-2017-16137 in version 3.2.0.

## Product
debug before 4.3.1.

## Impact
The impact of this vulnerability is considered low due to the low severity of the issue.

## Remediation
Update the debug dependency to 4.3.1 or above.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://www.twitter.com/ynizry).

## Resources
1. Commit [b6d12fd](https://github.com/visionmedia/debug/commit/b6d12fdbc63b483e5c969da33ea6adc09946b5ac)
2. [Issue](https://github.com/visionmedia/debug/issues/797)
