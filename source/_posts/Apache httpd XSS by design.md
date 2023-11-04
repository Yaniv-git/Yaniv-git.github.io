---
title: Apache httpd Stored XSS by design
date: 2023-11-05
tags:
	- "content-type"
	- "xss"
	- "apache"
advisory: false
origin: 
cves:
---
# Introduction
Approximately one year ago in 2022, I took part in a Capture The Flag (CTF) challenge with the objective of achieving Remote Code Execution (RCE). While tackling the challenge, I observed an unusual behavior that allowed for a Stored Cross-Site Scripting (XSS) attack by uploading a file, regardless of its extension. Upon closer investigation, I uncovered that the *"quirk"* was rooted in the Apache HTTP Server.

# TL;DR
By default, Apache httpd does not include the "no-sniff" header, `X-Content-Type-Options: nosniff`, and it does not perform automatic content type detection for files that lack a name or have only dots as their name, regardless of the file extension. For instance, a file named `.jpg` or `...jpg` would serve without any content type causing the browser to *"sniff"* the content, unlike files such as `test.jpg` which will result in `Content-type: image/jpeg`. This means that if an attacker has the capability to upload a file with no name or a name consisting solely of dots, it becomes possible to exploit a stored XSS vulnerability, regardless of the file extension's constraints.

<img src="/img/blogs/httpd/Image-1.png" style="width: 100%;"/>

# Background
## Content-type

In HTTP (Hypertext Transfer Protocol), the `Content-Type` header is used to indicate the media type or MIME (Multipurpose Internet Mail Extensions) type of the data that is being sent in the HTTP response. It specifies the format of the content being returned by the server so that the client (e.g., a web browser) knows how to properly interpret and display the data.

Here are some examples of common media types:

* `text/html`: Indicates that the content is HTML text.
* `text/plain`: Indicates that the content is plain text.
* `application/json`: Indicates that the content is JSON data.
* `application/xml`: Indicates that the content is XML data.
* `image/jpeg`, `image/png`, `image/gif`: Indicate that the content is an image in various formats.

This header is crucial for the client to interpret the received data correctly. If the client doesn't recognize or support the specified Content-Type, it may not be able to process the content as intended.

## Content-type Sniffing
Content-Type sniffing, is a behavior that web browsers and other user agents sometimes exhibit when they receive a resource with an ambiguous or missing Content-Type header. Content-Type sniffing involves the user agent trying to determine the media type of the resource by inspecting its actual content. 

The purpose of content-type sniffing is to improve the user experience by attempting to render the content in a way that makes sense to the user. However, it can also introduce security risks. For example, if an attacker can control the content of a resource and trick the browser into interpreting it as a different media type, and might lead to security vulnerabilities.

To mitigate these risks, modern browsers provide web developers the ability to to disable content sniffing by adding the header: `X-Content-Type-Options: nosniff`.

Content-Type sniffing should not be relied upon for determining the media type of a resource. Instead, it's best practice to always set the correct Content-Type header on the server side to ensure that the browser and other user agents can correctly process the content.

# Apache's response 
After reaching the maintainers of Apache httpd, they replied that this is the expected behavior of [mod_mime](https://httpd.apache.org/docs/2.4/mod/mod_mime.html) \(the component that generates a content-type according to a file\).

# References
* [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
* [Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)
* [mod_mime](https://httpd.apache.org/docs/2.4/mod/mod_mime.html)
* [Tweet](https://twitter.com/YNizry/status/1582733545759330306)
