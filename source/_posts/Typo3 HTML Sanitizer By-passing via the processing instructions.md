---
title: "Typo3 HTML Sanitizer By-passing via the processing instructions"
date: 2023-11-14
tags:
	- "xss"
	- "bypass"
advisory: true
origin: https://github.com/advisories/GHSA-mm79-jhqm-9j54
cves: 
	- CVE-2023-47125
ghsas:
	- "GHSA-mm79-jhqm-9j54"
---
# Problem
DOM processing instructions are not handled correctly. This allows bypassing the cross-site scripting mechanism of [typo3/html-sanitizer](https://packagist.org/packages/typo3/html-sanitizer).


# Solution
Update to `typo3/html-sanitizer` versions 1.5.3 or 2.1.4 that fix the problem described.

# Credits
Thanks to Yaniv Nizry and Niels Dossche who reported this issue, and to TYPO3 core & security team member Oliver Hader who fixed the issue.

# References
* [TYPO3-CORE-SA-2023-007](https://typo3.org/security/advisory/typo3-core-sa-2023-007)
* [Disclosure & PoC](https://github.com/TYPO3/html-sanitizer/security/advisories/GHSA-652v-xw37-rvw7) (embargoed +90 days)
