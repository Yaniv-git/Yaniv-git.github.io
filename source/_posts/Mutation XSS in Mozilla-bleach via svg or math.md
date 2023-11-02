---
title: Mutation XSS in Mozilla-bleach via svg or math
date: 2020-03-17
tags:
	- "python"
	- "mozilla"
	- "xss"
	- "mxss"
	- "bypass"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2020-4277/
cves:
	- "CVE-2020-6816"
---
## Summary
Mutation XSS (mXSS) vulnerability in Mozilla-bleach , when RCDATA and either svg or math tags are whitelisted and the keyword argument `strip=False`. It happens due to improper sanitization of the RCDATA tags (`script, noscript, style, noframes, xmp, noembed` and `iframe`) when placed under `svg` or `math`, allowing the browser to execute arbitrary HTML in RCDATA on the victim's browser.

## Product
Bleach before 3.1.2

## Impact
According to GitHub, more than 72,000 repositories are dependent on Bleach. Among them are major vendors, including multiple Fortune 500 tech companies.

## Steps to reproduce
```
>>> import bleach
>>> bleach.clean('<svg><style><img src=x onerror=alert(1)>', tags=["svg","style"])
```

### Expected result:
```<svg><style><img src=x onerror=alert(1)></style></svg>```

## Remediation
Update bleach dependency to 3.1.2 and above

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Blog](https://www.checkmarx.com/blog/vulnerabilities-discovered-in-mozilla-bleach)
2. [Advisory](https://github.com/mozilla/bleach/security/advisories/GHSA-m6xf-fq7q-8743)
3. Commit [175f677](https://github.com/mozilla/bleach/commit/175f67740e7951e1d80cefb7831e6c3e4efeb986)
