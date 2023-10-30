---
title: Mutation Cross-Site Scripting (mXSS) Vulnerabilities Discovered in Mozilla-Bleach
date: 2020-07-08
tags:
	- "python"
	- "mozilla"
	- "xss"
	- "mxss"
advisory: false
origin: https://checkmarx.com/blog/vulnerabilities-discovered-in-mozilla-bleach/
cves:
	- "CVE-2020-6802"
	- "CVE-2020-6816"
---
# Introduction
As part of the beta testing phase that took place earlier this year for our recently launched Software Composition Analysis solution, [CxSCA](https://www.checkmarx.com/product/cxsca-open-source-scanning/?), the Checkmarx Security Research Team investigated Mozilla-Bleach, finding multiple concerning security vulnerabilities. Patches were released in mid-March 2020, with Checkmarx CxSCA customers using Bleach receiving notice of the issues in advance. Given that the patches have been in-market for some time, giving Bleach users sufficient time to update their software versions, we’re now publishing the full technical report and [proof-of-concept](https://youtu.be/cJZg3qj7sz0) video for educational purposes.

# Overview
According to documentation, “Bleach is an allowed-list-based HTML sanitizing library that escapes or strips markup and attributes and is intended for sanitizing text from untrusted sources.” In simpler terms, Bleach is a very user-friendly HTML sanitizer, and its main purpose is to disallow arbitrary tags to run (e.g., JavaScript (JS) tags and attributes to prevent cross-site scripting (XSS)). After a bit of fuzzing and using some different approaches, Checkmarx researchers discovered the possibility that a mutation XSS (mXSS) vulnerability may exist. With further digging, these suspicions were confirmed, and several mXSS vulnerabilities were discovered in the Mozilla-Bleach python package. An attacker abusing these vulnerabilities would have the ability to execute an arbitrary JavaScript code on the user end, via various sites or projects that use Bleach.


# Mutation XSS (mXSS)
A mXSS vulnerability occurs when there is incoherent parsing between the client and the sanitizer. To understand this better, the following example should help. Let’s see how a standard browser interprets invalid HTML. When we enter the data below into the innerHTML of the page:

<img src="/img/blogs/mozilla-bleach/Image-1.png" style="width: 100%;"/>

The browser will modify the data to make it valid html. In this case, this is what the output looks like:

<img src="/img/blogs/mozilla-bleach/Image-2.png" style="width: 100%;"/>

Now let’s try to change the **div** tag to a different type of tag, for example:

<img src="/img/blogs/mozilla-bleach/Image-3.png" style="width: 100%;"/>

Doing so will generate the result below:

<img src="/img/blogs/mozilla-bleach/Image-4.png" style="width: 100%;"/>

Both examples act differently because the data inside the tags are parsed differently according to the tag type. Now, imagine the parser goes from left to right. In the first case, after entering the ***div*** tag, the parser stays as html and opens an ***a*** tag with the title attribute (because the “closing” ***div*** tag is text in an attribute, it will not close the tag). In the second case, when the parser enters the ***style*** tag, it changes to CSS parser, which means no ***a*** tag is created, and the ***style*** tag will be closed where the attribute was supposed to be. So, how can this information help us in finding vulnerabilities? Imagine a tag that parses differently in different cases, for example, the ***noscript*** tag. The trick here is that the ***noscript*** tag in HTML is treated differently, whether JavaScript (JS) is enabled or disabled. When JS is enabled, the data inside the tag is parsed as JS. But, when it’s disabled, the data is parsed as html. In nearly all cases, JS is enabled in browsers. Let’s take a look at how the following input is being interpreted with, and without, JS enabled:

<img src="/img/blogs/mozilla-bleach/Image-5.png" style="width: 100%;"/>

Here, JS is disabled:

<img src="/img/blogs/mozilla-bleach/Image-6.png" style="width: 100%;"/>

Here, JS is enabled:

<img src="/img/blogs/mozilla-bleach/Image-7.png" style="width: 100%;"/>

# Vulnerability: CVE-2020-6802

When we tried to pass the above input to Bleach, it sanitized the '***<***' characters in the attribute, but also it closed the ***a*** tag! This means that it parsed the data in ***noscript*** as html.

<img src="/img/blogs/mozilla-bleach/Image-8.png" style="width: 100%;"/>

In this case, the only thing left is to avoid this sanitization. If that wasn’t enough of a challenge, we attempted to enter another parsing into the equation.

<img src="/img/blogs/mozilla-bleach/Image-9.png" style="width: 100%;"/>

This provided the outcome we were anticipating. **Sanitizer view**: Enters ***noscript*** and the parser is **HTML**, opens a ***style*** tag, and starts parsing as CSS (or raw text). Everything after the ***style*** tag isn’t parsed as html, so from the sanitizer’s viewpoint, there is no closing ***noscript*** tag nor ***img*** tag. **Browser view**: Enters ***noscript*** and the parser is changed to JavaScript. Now the ***"&lt;style>"*** is just text, not a tag. As you can see, the closing tag, in this case, actually closes the ***noscript*** tag, and from there, everything is html. The conditions to successful exploitation are: ***noscript*** tag allowed as well as html comments, or one of the following tags: ***title, textarea, script, style, noembed, noframes, iframe, xmp***.

# Vulnerability: CVE-2020-6816

Shortly after, the Checkmarx Security Research Team discovered another mXSS vulnerability in Mozilla-Bleach, this time with the use of ***svg/math*** tags. The caveat here is that the parsing inside those tags is like XML. So, if we enter, for example, a ***style*** tag, the data inside will act differently, whether inside or outside. Inside an ***svg*** tag:

<img src="/img/blogs/mozilla-bleach/Image-10.png" style="width: 40%;"/>

Without an ***svg*** tag:

<img src="/img/blogs/mozilla-bleach/Image-11.png" style="width: 100%;"/>

This shows how differently the data inside the ***style*** tag is being parsed. In addition, some unwanted tags inside the ***svg/math*** will automatically pop out of the ***svg/math*** and will be parsed as HTML (e.g., ***&lt;img>***). When the team tried to put a malicious img tag in ***svg/math->style->img***, Bleach acted strangely. In case the ***img*** tag was whitelisted, it parsed it like the browser and sanitized unwanted attributes as expected. And when the **“strip”** variable was set to true (meaning it will delete unwanted data instead of sanitizing it, default is false), it got deleted. But in case **“strip”** was not changed, we could use any tag that wasn’t allowed and bypass Bleach.

<img src="/img/blogs/mozilla-bleach/Image-11.png" style="width: 100%;"/>

After further investigation, we saw that html5lib (the parser behind Bleach) does recognize the data inside ***svg->style*** as tags. But for some reason, Bleach doesn’t sanitize unwanted tags.

# Impact
According to GitHub, more than 72,000 repositories are dependent on Bleach. Among them are major vendors, including multiple Fortune 500 tech companies.

# Summary of Disclosure and Events
When the first vulnerability was discovered, our research team ensured that they could reproduce the process of exploiting it. Once that was confirmed, the Checkmarx team responsibly notified Mozilla of their findings. Subsequently, they opened a Bugzilla ticket where the team helped Mozilla find a proper mitigation approach, and they fixed the issue rapidly. Soon after that, the second vulnerability was discovered by the research team. Again, a responsible notification was sent to Mozilla, and a Bugzilla ticket was quickly opened and resolved. Checkmarx customers using CxSCA were automatically notified to update Mozilla-Bleach.

# Bugzilla Tickets
* CVE-2020-6802 - https://bugzilla.mozilla.org/show_bug.cgi?id=1615315 
* CVE-2020-6816 - https://bugzilla.mozilla.org/show_bug.cgi?id=1621692

# Timeline of Disclosure
| Date    | Action |
| -------- | ------- |
| 13-Feb-2020 | First vulnerability reported |
| 14-Feb-2020 | Checkmarx customers who were using Bleach were warned, without exposing the vulnerability's details |
| 19-Feb-2020 | Fixed version v3.1.1 and an advisory on GitHub was released |
| 25-Feb-2020 | CVE-2020-6802 was assigned |
| 11-Mar-2020 | Second vulnerability reported |
| 11-Mar-2020 | Checkmarx customers who were using Bleach were warned, without exposing the vulnerability's details |
| 17-Mar-2020 | Fixed version v3.1.2 and an advisory on GitHub was released |
| 19-Mar-2020 | CVE-2020-6816 was assigned |

# Final Words
Discovering vulnerabilities like the ones documented in this report is why the Checkmarx Security Research Team performs investigations into open source packages. With open source making up the vast majority of today’s commercial software projects, security vulnerabilities must be taken seriously and handled more carefully across the industry. Solutions like CxSCA are essential in helping organizations identify, prioritize, and remediate open source vulnerabilities more efficiently to improve their overall software security risk posture.

# References
* [XSS](https://owasp.org/www-community/attacks/xss/) 
* [mXSS](https://cure53.de/fp170.pdf)
* [CVE-2020-6802 advisory](https://github.com/mozilla/bleach/security/advisories/GHSA-q65m-pv3f-wr5r)
* [CVE-2020-6816 advisory](https://github.com/mozilla/bleach/security/advisories/GHSA-m6xf-fq7q-8743)
* [CVE-2020-6802 Bugzilla ticket](https://bugzilla.mozilla.org/show_bug.cgi?id=1615315) 
* [CVE-2020-6816 Bugzilla ticket](https://bugzilla.mozilla.org/show_bug.cgi?id=1621692) 