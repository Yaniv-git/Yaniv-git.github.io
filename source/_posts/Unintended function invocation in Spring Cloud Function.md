---
title: Unintended function invocation in Spring Cloud Function
date: 2021-06-17
tags:
	- "java"
	- "function"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2022-5010/
cves:
---
## Summary
In Spring Cloud Function it's possible for users to invoke unintended functions that follow some arbitrary rules. In versions 3.2.6 and above a `spring.cloud.function.ineligible-definitions` configuration was introduced to mitigate the issue but it still requires the user to go over the unintended functions a user might run.

## Product
Spring Cloud Function versions before 3.2.6.

## Impact
The impact is highly dependent on the application context, and on the worse case could lead to RCE. 

## Steps to reproduce
1. Run the  following main function: 
```
public static void main(String[] args) {
		Collection registeredBeans = new ArrayList<String>();
		ApplicationContext context = SpringApplication.run(DemoApplication.class, args);
		FunctionCatalog catalog = context.getBean(FunctionCatalog.class);
		System.out.println("Num of Beans: " + context.getBeanDefinitionNames().length);
		for (String functionName : context.getBeanDefinitionNames())
		{
			try
			{
				SimpleFunctionRegistry.FunctionInvocationWrapper function = (SimpleFunctionRegistry.FunctionInvocationWrapper)catalog.lookup(functionName);
				if (function != null)
				{
					registeredBeans.add(functionName);
				}
			}
			catch (Exception e)
			{
			}
		}
		System.out.println("Num of registered functions: " + registeredBeans.size());
		System.out.println(registeredBeans);
}

```
2. The output will list all of the functions a user can call, there will be more than the application's intention.

### Expected result:
Unintended functions could be executed, the impact could vary.

## Remediation
Update Spring Cloud Function to 3.2.6 or above, and use the configuration spring.cloud.function.ineligible-definitions to exclude unintended functions.

## Credit
This issue was discovered and reported by Checkmarx SCA Security Researcher [Yaniv Nizry](https://twitter.com/ynizry).

## Resources
1. [Commit](https://github.com/spring-cloud/spring-cloud-function/commit/1381cd4e6d04961d028683d2226242c01d7397ab)