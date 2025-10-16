---
title: "FortiGuard: “Access Blocked” Web Page XSS"
date: 2025-10-14
tags:
    - "fortinet"
    - "fortiguard"
    - "fortios"
    - "fortisase"
    - "fortiproxy"
    - "xss"
    - "uxss"
advisory: true
cves:
	- "CVE-2025-31366"
---
### Background

FortiGuard can be configured with specific web locations/patterns that should be filtered. When a client visits such a URL, it can block it, show a warning, monitor it, or authenticate the user. We noticed that the default warning page when visiting such a link doesn't properly handle the URL, which can result in XSS on "warned" domains.

### Exploitation

On the generated page, the URL is embedded inside the onclick event handler of the "Proceed" button using the following code:
```js
document.location.href='https://warned_domain:8010/warn?fblob=*blob*&uri=*uri*';  return  false;
```
The URI parameter isn't sanitized and can contain a single-quote character, which will escape the string and inject arbitrary JavaScript code that gets executed when a victim clicks on "proceed". Since the warning page is running on the same domain as the "blocked" domain, the XSS will be in the context of that domain. 

<img src="/img/blogs/fortinet/advisories/fortiguard_button_html.png" style="width: 100%;"/>

Payload example: `https://warned_domain/static';alert(document.domain);a='`

<video controls="" src="/videos/fortinet/fortiguard_XSS.mov" style="width: 100%;"></video>

### Impact
In conjunction with ["Caught in the FortiNet"](https://www.sonarsource.com/blog/caught-in-the-fortinet-how-attackers-can-exploit-forticlient-to-compromise-organizations-1-3/) research, a FortiClient can connect to a malicious server by a simple click, potentially changing to an attacker-controlled FortiGuard with arbitrary configuration. 
By defining arbitrary domains as "warn domains" (for example, `google.com`), and then using the mishandeling of the SAML URL (the EMS can send a SAML registration reply starting with `@` character instead of `/`: 
`FCREGRPLY: REG|14|AUTHTYPE|3|AUTHSAML|@google.com|ERR_MSG|Authentication error|`) it will cause FortiClient to open automatically arbitrary "warn domains" in the victim's browser. If the victim then clicks on `proceed` an XSS on arbitrary domains will trigger (UXSS).
An attacker can then steal cookies and sensitive data, impersonate victims, and more, depending on the website's logic.

## Affected Product
- FortiOS before version 7.4.8, FortiOS 7.6.0 through 7.6.3 
- FortiProxy before version 7.6.3
- FortiSASE version 25.3.a

## Remediation
- FortiOS: Update to 7.6.4, 7.4.9 or above
- FortiProxy: Update to 7.6.4 or above

## Additional Resources
- ["Caught in the FortiNet" blogs](https://www.sonarsource.com/blog/caught-in-the-fortinet-how-attackers-can-exploit-forticlient-to-compromise-organizations-1-3/)
- [Fortinet's Advisory](https://www.fortiguard.com/psirt/FG-IR-24-542)
- [CVE-2025-31366](https://nvd.nist.gov/vuln/detail/CVE-2025-31366)
