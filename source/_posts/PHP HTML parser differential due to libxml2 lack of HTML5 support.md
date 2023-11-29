---
title: "PHP HTML parser differential due to libxml2 lack of HTML5 support"
date: 2023-11-29
tags:
	- "parser differential"
	- "xss"
	- "mxss"
	- "bypass"
advisory: true
origin: 
cves:
ghsas:
---
### Summary
The default HTML parser of PHP uses the underlying package libxml2 ([for example here](https://github.com/php/php-src/blob/master/ext/dom/document.c#L1920)). Libxml2 doesn’t [currently support](https://gitlab.gnome.org/GNOME/libxml2/-/issues/211) HTML5 parsing, and while it is undergoing process, after contacting them about this matter they said it will take a while before implementing this feature. This means that the built-in HTML parser of PHP behind [loadHTML](https://www.php.net/manual/en/domdocument.loadhtml.php), [DOMImplementation](https://www.php.net/manual/en/class.domimplementation.php), etc. does not follow the same parsing rules as modern web browsers.
This behaviour becomes security-relevant when HTML sanitizers use the built-in HTML parser.
We have come across multiple PHP sanitizers that are vulnerable to bypasses due to using the built-in parser, and we think that the root cause can't be addressed without significant changes by libxml2.

### PoC
Here are some examples of how attackers can leverage these parsing differentials in order to bypass sanitizers.

#### 1. Comments:
According to the [XML specification](https://www.w3.org/TR/xml/#sec-comments) (XHTML), comments must end with the characters `—>`. On the other hand, the [HTML specification](https://html.spec.whatwg.org/multipage/syntax.html#comments) states that a comment's text “must not start with the string `>`, nor start with the string `->`”.
When parsing the following string in a browser, the comment will end before the `p` tag. But when parsing with PHP the `p` tag will be considered `a` comment:
```
Input: <!--><p>
Browser (HTML specification) output: <!----><p></p>
PHP parser (XHTML specification) output: <!--><p>-->
```
This can be done with either `<!-->` or `<!--->`.
An attacker can input the following payload `<!--><xss>-->`. While the parser considers the xss tag as a comment, the browser will end the comment right before and render the xss tag as expected.

#### 2. RCDATA/RAWTEXT elements
In [HTML5](https://html.spec.whatwg.org/#parsing-html-fragments), other element parsing types were introduced: 
* RCDATA
    * textarea
    * title 
* RAWTEXT
    * noframes
    * noembed
    * iframe
    * xmp
    * style
* OTHERS
    * noscript - depends if [scripting](https://html.spec.whatwg.org/#the-noscript-element) is enabled (enabled by default in browsers).
    * plaintext
    * script

While the PHP’s parser is oblivious to that. There are multiple ways an attacker can bypass a sanitizer due to wrong parsing such as:
* `<iframe><!--</iframe><xss>--></iframe>`
* `<noframes><style></noframes><xss></style></noframes>`
* ...
#### 3. Foreign content elements
HTML5 introduced two foreign elements ([math](https://html.spec.whatwg.org/#mathml) and [svg](https://html.spec.whatwg.org/#svg-0)) which follow different parsing specifications than HTML. Again parsing with PHP doesn’t take it into account, causing other parsing differentials and sanitizers bypass such as:
* `<svg><p><style><!--</style><xss>--></style>` 
* ...

#### 4. DOCTYPE element
The `!DOCTYPE` [element in XML/XHTML](https://www.w3.org/TR/xml/#NT-doctypedecl) is more complex allowing more characters and element nesting than in [HTML5](https://html.spec.whatwg.org/#the-doctype). In contrast, the HTML doctype ends with the [first occurrence](https://html.spec.whatwg.org/#doctype-state) of the “greater than” sign `>`.
Parsing the following string will render an xss tag in the browser but not in PHP:
* `<!DOCTYPE HTML PUBLIC "-//W3C//DTDHTML4.01//EN" "><xss>">` 
* `<!DOCTYPE HTML SYSTEM "><xss>">`

### Impact
Sanitizers using the built-in PHP parser are inherently vulnerable to bypass due to wrong parsing.

### Recommendation
This issue is [known](https://wiki.php.net/rfc/domdocument_html5_parser) but isn't clear for users of PHP, after this report the PHP team added a red warning to the documentation:

* [loadhtml](https://www.php.net/manual/en/domdocument.loadhtml.php)
* [loadhtmlfile](https://www.php.net/manual/en/domdocument.loadhtmlfile.php)
* [Commit](https://github.com/php/doc-en/commit/4ef716f8aa753e1189b2e57c91da378b16d970b0)