---
title: Apache httpd XSS Using Multiple Extensions
date: 2025-07-08
tags:
	- "content-type"
	- "xss"
	- "apache"
advisory: false
origin: 
cves:
---
# Introduction
This post dives into a stored Cross-Site Scripting (XSS) technique I discovered while researching Fortinet's endpoint protection solution. It builds on previous work, specifically [part two](https://yaniv-git.github.io/2025/06/29/Caught%20in%20the%20FortiNet:%20How%20Attackers%20Can%20Exploit%20FortiClient%20to%20Compromise%20Organizations%202/#From-Limited-File-Write-to-XSS-CVE-2025-22859) of my series (CVE-2025-22859), where I detailed an `httpd` stored XSS vulnerability using a files with a predefined extensions.

I have already [covered](https://yaniv-git.github.io/2023/11/04/Apache%20httpd%20XSS%20by%20design/) a small technique of achieving XSS on `httpd` when the attacker can't control the file extension. However, unlike that prior method, which involved creating files with no name or only dots to bypass extension assignage, this new trick doesn't depend on the absense of the `X-Content-Type-Options: nosniff` header. Complicating the other writeup, making these nice to add to our toolbox.

# Details

The core of this technique lies in how [Apache httpd's](https://httpd.apache.org/) [mod_mime](https://httpd.apache.org/docs/2.4/mod/mod_mime.html) module determines a file's `Content-Type`. Typically, `mod_mime` guesses the content type based on the file's extension. If the `X-Content-Type-Options: nosniff` header is present, browsers are instructed not to "sniff" the content type and will default to `text/plain` when an `Content-Type` isn't set. However, a closer look at the `mod_mime` documentation reveals an interesting behavior: 

<img src="/img/blogs/fortinet/2/mod_mime_doc.png" style="width: 100%;"/>

Files can have [multiple extensions](https://httpd.apache.org/docs/2.4/mod/mod_mime.html#multipleext "multiple extensions"), with a priority given to the last one. For example, these file extensions will correspond to the following content-types:

| File Extension    | mod_mime Content-Type |
| -------- | ------- |
|Filename.**html** | text/html |
|Filename.**gif** | image/gif |
|Filename.gif.**html** | text/html |
|Filename.**unknown** |  |
|Filename.unknown.**html** | text/html |
|Filename.**html**.unknown | text/html |

# The Attack Scenario
Armed with this knowledge, in a scenario where an attacker has the ability to upload a file, but can't control the extension. If the extension doesn't correlate to any content type in `mod_mime` (for example `.abc`),  all the attacker would need to do is to add `.html` to the filename (`filename.html.abc`). When Apache serves this file, `mod_mime` will process the multiple extensions, recognize `.html` as the last and most significant one since `.abc` doesnt cererlate ot anything, and serve the file with `Content-Type: text/html`, resulting in stored XSS. This technique might also be used to bypass some server-side validation that only permits specific file types.

# References
* [CVE-2025-22859 blog](https://yaniv-git.github.io/2025/06/29/Caught%20in%20the%20FortiNet:%20How%20Attackers%20Can%20Exploit%20FortiClient%20to%20Compromise%20Organizations%202/#From-Limited-File-Write-to-XSS-CVE-2025-22859)
* [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
* [Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)
* [mod_mime](https://httpd.apache.org/docs/2.4/mod/mod_mime.html)
* [Tweet](https://x.com/YNizry/status/1940053407127007587)