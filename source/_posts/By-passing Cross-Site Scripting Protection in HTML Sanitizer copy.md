---
title: "HtmlSanitizer vulnerable to Cross-site Scripting in Foreign Content"
date: 2023-10-04
tags:
	- "xss"
	- "mxss"
	- "bypass"
advisory: true
origin: https://github.com/advisories/GHSA-43cp-6p3q-2pc4
cves: 
	- CVE-2023-44390
ghsas:
	- "GHSA-43cp-6p3q-2pc4"
---
# Impact
The vulnerability occurs in configurations where foreign content is allowed, i.e. either `svg` or `math` are in the list of allowed elements.
Specifically, the requirements for the vulnerability are:

1. Allowing one foreign element: `svg`, or `math`
2. Comments or one raw text element: `iframe`, `noembed`, `xmp`, `title`, `noframes`, `style` or `noscript`

Configurations that meet the above requirements plus the following are vulnerable to an additional vulnerability:

* Any HTML integration element: `title`, `desc`, `mi`, `mo`, `mn`, `ms`, `mtext`, `annotation-xml`.

In case an application sanitizes user input with a vulnerable configuration, an attacker could
bypass the sanitization and inject arbitrary HTML, including JavaScript code.

Note that in the default configuration the vulnerability is not present.

# Patches
The vulnerability has been fixed in versions 8.0.723 and 8.1.722-beta (preview version).

# Workarounds
Disallow foreign elements `svg` and `math`. This is the case in the default configuration, which is therefore not affected by the vulnerability.

# References
* [GHSA-43cp-6p3q-2pc4](https://github.com/mganss/HtmlSanitizer/security/advisories/GHSA-43cp-6p3q-2pc4)
* [mganss/HtmlSanitizer@ab29319](https://github.com/mganss/HtmlSanitizer/commit/ab29319866c020f0cc11e6b92228cd8039196c6e)
* https://nvd.nist.gov/vuln/detail/CVE-2023-44390

