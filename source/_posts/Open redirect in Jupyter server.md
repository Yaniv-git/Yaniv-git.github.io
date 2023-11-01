---
title: Open redirect in Jupyter server
date: 2020-12-17
tags:
	- "python"
	- "open redirect"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2020-4291/
cves:
	- "CVE-2020-26275"
ghsas:
	- "GHSA-9f66-54xg-pc2c"
---
## Summary
The Jupyter Server provides the backend (i.e. the core services, APIs, and REST endpoints) for Jupyter web applications like Jupyter notebook, JupyterLab, and Voila. Affected versions of Jupyter Server are vulnerable to open redirect vulnerability. All jupyter servers running without a base_url prefix are technically affected, however, these maliciously crafted links can only be reasonably made for known jupyter server hosts.

## Product
Jupyter Server before version 1.1.1

## Impact
A link to a jupyter server may appear safe, but ultimately redirect to a malicious site.

## Steps to reproduce
1. Run a jupyter server on port 1111
2. Navigate to ```http://localhost:1111/login?next=//example.com```

### Expected result:
`https://example.com` will load.

## Remediation
Use on of the two options:
1. Update jupyter_server package to 1.1.1 or above.
2. Run your server on a url prefix: "jupyter server --ServerApp.base_url=/jupyter/".

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Advisory](https://github.com/advisories/GHSA-9f66-54xg-pc2c)
2. Commit [85e4abc](https://github.com/jupyter-server/jupyter_server/commit/85e4abccf6ea9321d29153f73b0bd72ccb3a6bca)
