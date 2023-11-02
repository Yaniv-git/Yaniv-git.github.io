---
title: "@vendure/admin-ui-plugin authenticated XSS"
date: 2023-07-04
tags:
    - "xss"
    - "npm"
advisory: true
origin: https://github.com/advisories/GHSA-gm68-572p-q28r
cves:
ghsas:
	- "GHSA-9f66-54xg-pc2c"
---
## Impact
Vendure provides an authorization system with different levels of privileges. For example, an administrator cannot create another administrator.

In the admin UI, there are a couple of places with description inputs, such as inventory/collection catalog, shipping methods, promotions, and more.

While the WYSIWYG editor allows limited customization, altering the request data (not in the ui) saves and returns arbitrary HTML with no sanitization. Causing an XSS when viewing the page.

The impact of this XSS is privilege escalation. A user that can write any type of description can trigger the attack. Then any other user that visits the vulnerable page is prone to arbitrary Javascript code execution, giving the attacker ability to execute actions on behalf of this user.

# Patches
Update to versions 2.0.3 or above.

# Workarounds
Is there a way for users to fix or remediate the vulnerability without upgrading?

# References
Are there any links users can visit to find out more?
* [GHSA-gm68-572p-q28r](https://github.com/vendure-ecommerce/vendure/security/advisories/GHSA-gm68-572p-q28r)
* [vendure-ecommerce/vendure@0cdc92b](https://github.com/vendure-ecommerce/vendure/commit/0cdc92b241e6fd4017ddfc9fbdca189fc7c1ada0)
* https://github.com/vendure-ecommerce/vendure/blob/master/CHANGELOG.md#203-2023-07-04