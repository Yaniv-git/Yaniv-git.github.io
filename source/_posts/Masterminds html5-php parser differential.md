---
title: "Masterminds/html5-php parser differential"
date: 2023-11-14
tags:
	- "parser differential"
	- "xss"
	- "mxss"
	- "bypass"
advisory: true
origin: https://github.com/Masterminds/html5-php/issues/241
cves:
ghsas:
---
## Observations
We have noticed a number of parsing differences between the Masterminds/html5-php parser and the HTML5 specification. We think that the root cause of those issues drills down to the [use](https://github.com/Masterminds/html5-php/blob/master/src/HTML5/Parser/DOMTreeBuilder.php#L172) of PHP’s default parser, [loadHTML](https://www.php.net/manual/en/domdocument.loadhtml.php), [DOMImplementation](https://www.php.net/manual/en/class.domimplementation.php), etc. The lack of HTML5 support by PHP is [known](https://wiki.php.net/rfc/domdocument_html5_parser) and we contacted them asking to make it more clear in the [documentation](https://www.php.net/manual/en/domdocument.loadhtml.php) in order to raise awareness for these security issues.
This behavior becomes security-relevant when HTML sanitizers use the Masterminds/html5-php parser. We have come across multiple PHP sanitizers that are vulnerable to bypasses due to using Masterminds/html5-php.

## Exploitation
Here are examples of the differentials, and how attackers can leverage these in order to bypass sanitizers.

### Comments:
According to the [XML specification](https://www.w3.org/TR/xml/#sec-comments) (XHTML), comments must end with the characters `-->`.
On the other hand, the [HTML specification](https://html.spec.whatwg.org/multipage/syntax.html#comments) states that a comment's text _'must not start with the string `>`, nor start with the string `->`'_.
When parsing the following string in a browser, the comment will end before the `p` tag. But when parsing with `Masterminds/html5-php` the `p` tag will be considered a comment:
* Input: `<!---><p>`
* Browser (HTML5 specification) output: `<!----><p></p>`
* Masterminds/html5-php parser output: `<!---><p>-->`

An attacker can input the following payload `<!---><xss>-->`. While the parser considers the `xss` tag as a comment, the browser will end the comment right before and render the `xss` tag as expected.

### Processing instructions (PI) elements ([known](https://github.com/Masterminds/html5-php#known-issues-or-things-we-designed-against-the-spec), but we encounter sanitizer bypasses due to this)
Processing instructions elements exist in [XML specification](https://www.w3.org/TR/xml/#sec-pi) but in [HTML5](https://html.spec.whatwg.org/#determining-the-character-encoding:~:text=A%20sequence%20of%20bytes%20starting%20with%3A%200x3C%200x3F%20(%60%3C%3F%60)) the characters `<?` opens a comment and ends it at the first occurrence of greater than `>`.

Attackers can create the following Processing Instruction `<?xml >s<img src=x onerror=alert(1)> ?>` and while no `img` tag is rendered in Masterminds/html5-php the browser will create a comment and end it at the first `>` character, rendering the `img` tag.

### Foreign content elements
HTML5 introduced two foreign elements ([math](https://html.spec.whatwg.org/#mathml) and [svg](https://html.spec.whatwg.org/#svg-0)) which follow different parsing specifications than HTML. Masterminds/html5-php doesn’t take it into account, causing other parsing differentials and [sanitizers bypass](https://research.securitum.com/dompurify-bypass-using-mxss/) such as:
* `<svg><p><style><!--</style><xss>--></style>`

### `noscript` element
Depending if [scripting](https://html.spec.whatwg.org/#the-noscript-element) is enabled (enabled by default in browsers) the `noscript` element parses its content differently:
* If scripting is enabled, then the content is rendered as raw data
* If scripting is disabled, then the content is rendered as HTML

Masterminds/html5-php parses according to disabled scripting, which is different than the default browsers’ parsing.
This is not wrong per se, but still can cause some [mXSS](https://cure53.de/fp170.pdf) such as:
`<noscript><p alt="</noscript><img src=x onerror=alert(1)>">`