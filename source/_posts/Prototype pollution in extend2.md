---
title: Prototype pollution in extend2
date: 2021-06-28
tags:
	- "npm"
	- "prototype-pollution"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4800/
cves:
---
## Summary
Affected versions of extend2 (npm) are vulnerable to prototype pollution via the extend function.

## Product
All versions of extend2 (npm).

## Impact
If untrusted data reaches one of the affected functions, prototype pollution can be achieved. The impact will depend on the application.

## Steps to reproduce
```js
const extend = require('extend2');
a = {'a':1};
extend(true, {}, a, JSON.parse('{"__proto__":{"polluted":1}}'));
console.log({}.polluted);
```

### Expected result:
1 will be printed to the console.

## Remediation
Currently no fix has been released. As a workaround, avoid passing untrusted inputs to the vulnerable function.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [NPM Package](https://www.npmjs.com/package/extend2)
