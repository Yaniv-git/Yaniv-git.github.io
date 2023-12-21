---
title: "SSRF in Gradio"
date: 2023-12-21
tags:
	- "ssrf"
	- "dos"
advisory: true
origin: https://github.com/advisories/GHSA-6qm2-wpxq-7qh2
cves: 
	- CVE-2023-51449
ghsas:
	- "GHSA-6qm2-wpxq-7qh2"
---
# Description
Older versions of `gradio` contained a vulnerability in the `/file` route which made them susceptible to file traversal attacks in which an attacker could access arbitrary files on a machine running a Gradio app with a public URL (e.g. if the demo was created with `share=True`, or on Hugging Face Spaces) if they knew the path of files to look for.

This was not possible through regular URLs passed into a browser, but it was possible through the use of programmatic tools such as `curl` with the `--pass-as-is` flag.

Furthermore, the `/file` route in Gradio apps also contained a vulnerability that made it possible to use it for SSRF attacks.

# Explotation
The exploitation of this vulnerability is highly context/infrastructure dependent. We found out that it is possible to DoS the gradio’s server simply by running the following request:
`http://gradio-domain/file=http://gradio-domain`

# Mitigation
Both of these vulnerabilities have been fixed in `gradio==4.11.0`

# References
* [Github's Advisory](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)