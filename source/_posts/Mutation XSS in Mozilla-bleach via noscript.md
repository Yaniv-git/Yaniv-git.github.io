---
title: Mutation XSS in Mozilla-bleach via noscript
date: 2020-02-25
tags:
	- "python"
	- "mozilla"
	- "xss"
	- "mxss"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2020-4276/
cves:
	- "CVE-2020-6802"
---
## Summary
Mutation XSS (mXSS) vulnerability in Mozilla-bleach when `noscript` tag is allowed in addition to one of the following tags: `title, textarea, script, style, noembed, noframes, iframe, xmp or comment`. 

This occurs due to bleach utilizing its parser, html5lib, with `scripting=False`. In this case, the data of the noscript tags will be parsed as HTML, while the browser parses them as rawdata. 
This can cause arbitrary HTML and JavaScript codes to run on the victim's browser.

## Product
Bleach before 3.1.1

## Impact
According to GitHub, more than 72,000 repositories are dependent on Bleach. Among them are major vendors, including multiple Fortune 500 tech companies.

## Steps to reproduce
```
>>> import bleach
>>> bleach.clean('<noscript><style></noscript><img src=x onerror=alert(1)>', tags=["noscript","style"])
```

### Expected result:
```<noscript><style></noscript><img src=x onerror=alert(1)></style></noscript>```

## Remediation
Update bleach dependency to 3.1.1 and above

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Blog](https://www.checkmarx.com/blog/vulnerabilities-discovered-in-mozilla-bleach)
2. [Advisory](https://github.com/mozilla/bleach/security/advisories/GHSA-q65m-pv3f-wr5r)
3. Commit [f77e0f6](https://github.com/mozilla/bleach/commit/f77e0f6392177a06e46a49abd61a4d9f035e57fd)
