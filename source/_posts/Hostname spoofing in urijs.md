---
title: Hostname spoofing in urijs
date: 2021-02-13
tags:
	- "javascript"
	- "improper validation"
	- "spoofing"
	- "npm"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4305/
cves:
	- "CVE-2021-27516"
ghsas:
  - "GHSA-p6j9-7xhc-rhwp"
---
## Summary
Affected versions of urijs fails to validate the hostname correctly when using backslash in the protocol e.g. `http:\/`.
Browsers accept backslashes after the protocol, and treat it as a normal slash, while urijs sees it as a relative path.

## Product
urijs before 1.19.6.

## Impact
Depending on library usage and attacker intent, impacts may include allow/block list bypasses, SSRF attacks, open redirects, or other undesired behavior.

## Steps to reproduce
```
var URI = require('urijs');
URI('http:/\www.google.com');
```

### Expected result:
the url would be relative without a hostname:
```
URI { 
  _string: '', 
  _parts: { 
    protocol: 'http', 
    username: null, 
    password: null, 
    hostname: null, 
    urn: true, 
    port: null, 
    path: '/www.google.com', 
    query: null, 
    fragment: null, 
    preventInvalidHostname: false, 
    duplicateQueryParameters: false, 
    escapeQuerySpace: true 
  }, 
  _deferred_build: true 
} 
```

## Remediation
Update urijs dependency to 1.19.6 or above.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://www.twitter.com/ynizry).

## Resources
1. Commit [a1ad8bc](https://github.com/medialize/URI.js/commit/a1ad8bcbc39a4d136d7e252e76e957f3ece70839)
2. [Release note](https://github.com/medialize/URI.js/releases/tag/v1.19.6)
3. [Advisory](https://github.com/medialize/URI.js/security/advisories/GHSA-p6j9-7xhc-rhwp)
