---
title: "Excessive Expansion: Uncovering Critical Security Vulnerabilities in Jenkins"
date: 2024-01-24
tags:
    - "java"
    - "rce"
    - "jenkins"
    - "arbitrary file read"
advisory: false
origin: https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/
cves:
    - "CVE-2024-23897"
    - "CVE-2024-23898"
star: true
---
# Key Information
* Sonar’s Vulnerability Research Team has discovered security vulnerabilities in Jenkins, the leading open-source Continuous Integration and Continuous Deployment (CI/CD) software.
* The discovered Critical vulnerability tracked as CVE-2024-23897 allows unauthenticated attackers to read a limited amount of arbitrary files’ data, and "read-only" authorized attackers to an entire arbitrary file from Jenkins’ server.
* Attackers could leverage this vulnerability, by reading Jenkins secrets, to escalate privileges to admin and eventually execute arbitrary code on the server.
* The discovered High severity, cross-site WebSocket hijacking (CSWSH), vulnerability tracked as CVE-2024-23898, allows an attacker to execute arbitrary CLI commands by manipulating a victim to click on a link.
* The vulnerabilities were fixed in Jenkins versions 2.442, and LTS 2.426.3.

Jenkins is the leading open-source automation server widely used for building, deploying, and automating software projects. Originally developed as Hudson, Jenkins has evolved into a powerful tool for continuous integration and continuous delivery (CI/CD). It enables developers to automate various aspects of the software development lifecycle, including building, testing, and deploying applications. With a market share of approximately [44% in 2023](https://cd.foundation/announcement/2023/08/29/jenkins-project-growth/), the popularity of Jenkins is evident. This means the potential impact of security vulnerabilities in Jenkins is large.

# Vulnerabilities Impact
Unauthenticated attackers can read the first few lines of arbitrary files from the server, while read-only authorized attackers can read the entire file. This could ultimately lead to the execution of arbitrary code in some cases (CVE-2024-23897). If one of the following conditions is met, even unauthenticated users have at least read permission:
* Legacy mode authorization is enabled.
* Configuration “Allow anonymous read access” is checked in the “logged-in users can do anything” authorization mode.
* The signup feature is enabled.

The second vulnerability (CVE-2024-23898) resides within the WebSocket CLI feature, which lacks an origin check, allowing Cross-Site WebSocket Hijacking (CSWSH). This vulnerability might be exploited by sending a malicious link to a victim. Certain modern web browsers implement a “[lax by default](https://caniuse.com/mdn-http_headers_set-cookie_samesite_lax_default)” policy, which serves as a potential safeguard against this vulnerability. Nonetheless, given that some widely used browsers like Safari and Firefox do not strictly enforce this policy, and considering the associated risks of potential [bypass](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#bypassing-samesite-lax-restrictions-with-newly-issued-cookies) techniques or users using outdated browsers, the severity classification for this vulnerability is High.
<iframe width="736" height="414" src="https://www.youtube.com/embed/ucs-XF5X3bE" title="Excessive Expansion: Uncovering Critical Security Vulnerabilities in Jenkins" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

# Technical Details
In this section of the blog, we will explore our findings taking a deeper dive into the code, to understand the vulnerabilities and how an attacker could exploit them. During the Jenkins security team’s triaging of our report, they found further ways to exploit the first vulnerability (CVE-2024-23897) using an unauthenticated user. The following "Technical Details" covers the attack scenario of a read-only capable attacker. 

# Background
Jenkins provides multiple ways of authorization, the unsafe *“anyone can do anything”*, the *“legacy”* permissions, and *“logged-in users can do anything”*. The latter authorization method allows the option for anonymous read access and gives read permission to anyone, which is also the case in the *legacy* mode.

<img src="/img/blogs/jenkins/image_1.webp" style="width: 100%;"/>

On top of that, there is also the not recommended option to *“Allow users to sign up”*, which makes everyone at least read-only capable.

According to the [official documentation](https://www.jenkins.io/doc/book/security/access-control/permissions/#overall-read), read-only access allows users to:

* Access the basic Jenkins API and the API of any object they have access to.
* Access the people directory listing user accounts and known committer identities of anyone involved in visible projects.
* List and view all agents configured in Jenkins and access their summary pages.

On the other hand, [administrators](https://www.jenkins.io/doc/book/security/access-control/permissions/#administer) can pretty much do everything on a Jenkins instance. From an attacker's point of view, admins can run arbitrary code on a Jenkins server.

# Jenkins-CLI Feature Background

[Jenkins-CLI](https://www.jenkins.io/doc/book/managing/cli/) provides users with a built-in command line interface to execute custom commands that are implemented in the [hudson/cli](https://github.com/jenkinsci/jenkins/tree/jenkins-2.441/core/src/main/java/hudson/cli) directory of the Jenkins Git repository.

Aside from the common ways of invoking a command, using `jenkins-cli.jar` (which utilizes web sockets) or SSH, we found out that there is an additional option by sending two POST requests to `http://jenkins/cli?remoting=false`.

When [Stapler](https://github.com/jenkinsci/stapler) (Jenkins' component that correlates a method to an endpoint) is [getting](https://github.com/jenkinsci/stapler/blob/ea4fc6ed8cd1b5eca6b4ce80b35654da9376e2bc/core/src/main/java/org/kohsuke/stapler/Stapler.java#L725) the relevant method of the *“/cli”* path, the endpoint will throw a [PlainCliEndpointResponse()](https://github.com/jenkinsci/jenkins/blob/3b0de10df3bedba515e13032104d4d84f83045be/core/src/main/java/hudson/cli/CLIAction.java#L195) exception, which will end up in this [generateResponse](https://github.com/jenkinsci/jenkins/blob/824f64c23e52e5c765cc7604414740aab3436f8d/core/src/main/java/jenkins/util/FullDuplexHttpService.java#L166) function:

```java
public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
    try {
        UUID uuid = UUID.fromString(req.getHeader("Session"));
        //...
        if (req.getHeader("Side").equals("download")) {
            FullDuplexHttpService service = createService(req, uuid);
            //...
            try {
                service.download(req, rsp);
            }
            //...
        } else {
            FullDuplexHttpService service = services.get(uuid);
            //...
            try {
                service.upload(req, rsp);
            }
            //...
}
}
```

This function requires a downloader and uploader. The downloader returns the command’s response, and the uploader invokes a specified command from the body of the request. Jenkins connects them (downloader and uploader) using the UUID from the `​​Session` header.

# Data Leak Vulnerability (CVE-2024-23897)
When invoking a CLI command with arguments, we have noticed that Jenkins uses [args4j’s](https://github.com/kohsuke/args4j) [parseArgument](https://github.com/jenkinsci/jenkins/blob/3b0de10df3bedba515e13032104d4d84f83045be/core/src/main/java/hudson/cli/CLICommand.java#L248), which [calls](https://github.com/kohsuke/args4j/blob/fc458a24d6bd08b58fdd0bd7e37acb08200eac59/args4j/src/org/kohsuke/args4j/CmdLineParser.java#L479) [expandAtFiles](https://github.com/kohsuke/args4j/blob/fc458a24d6bd08b58fdd0bd7e37acb08200eac59/args4j/src/org/kohsuke/args4j/CmdLineParser.java#L548):

```java
private String[] expandAtFiles(String args[]) throws CmdLineException {
    List<String> result = new ArrayList<String>();
    for (String arg : args) {
        if (arg.startsWith("@")) {
            File file = new File(arg.substring(1));
            if (!file.exists())
                throw new CmdLineException(this,Messages.NO_SUCH_FILE,file.getPath());
            try {
                result.addAll(readAllLines(file));
            } catch (IOException ex) {
                throw new CmdLineException(this, "Failed to parse "+file,ex);
            }
        } else {
            result.add(arg);
        }
    }
    return result.toArray(new String[result.size()]);
}
```
The function checks if the argument starts with the `@` character, and if so, it reads the file in the path after the `@` and expands a new argument for each line. 

<img src="/img/blogs/jenkins/image_2.webp" style="width: 100%;"/>

This means that if an attacker can control an argument, they can expand it to an arbitrary number of ones from an arbitrary file on the Jenkins instance.

One way an attacker could leverage this is to find a command that takes an arbitrary number of arguments and displays these back to the user. Since the arguments are populated from the contents of the file, an attacker could leak the file contents this way. We found the command [connect-to-node](https://github.com/jenkinsci/jenkins/blob/jenkins-2.441/core/src/main/java/hudson/cli/ConnectNodeCommand.java) to be a good candidate: it receives a [list of strings as an argument](https://github.com/jenkinsci/jenkins/blob/824f64c23e52e5c765cc7604414740aab3436f8d/core/src/main/java/hudson/cli/ConnectNodeCommand.java#L46) and tries to connect to each one. If it fails, an error message is generated with the name of the failed connected node. 

```java
public class ConnectNodeCommand extends CLICommand {
    //...
    @Argument(metaVar = "NAME", usage = "Agent name, or empty string for built-in node; comma-separated list is supported", required = true, multiValued = true)
    private List<String> nodes;
    //...

    @Override
    protected int run() throws Exception {
        //...
        for (String node_s : hs) {
            try {
                Computer computer = Computer.resolveForCLI(node_s);
                computer.cliConnect(force);
            } catch (Exception e) {
                //...
                final String errorMsg = node_s + ": " + e.getMessage();
                stderr.println(errorMsg);
                //...
            }
        }
        //...
    }
}
```
This [connect-to-node](https://github.com/jenkinsci/jenkins/blob/jenkins-2.441/core/src/main/java/hudson/cli/ConnectNodeCommand.java) command would usually require the CONNECT permission, which is verified in the [cliConnect](https://github.com/jenkinsci/jenkins/blob/3b0de10df3bedba515e13032104d4d84f83045be/core/src/main/java/hudson/model/Computer.java#L483) function. But since the exception is thrown before the permission check in the [resolveForCLI](https://github.com/jenkinsci/jenkins/blob/3b0de10df3bedba515e13032104d4d84f83045be/core/src/main/java/hudson/model/Computer.java#L1676) function, the command actually doesn’t require any authorizations apart from the initial [read-only verification](https://github.com/jenkinsci/jenkins/blob/3b0de10df3bedba515e13032104d4d84f83045be/core/src/main/java/hudson/cli/CLICommand.java#L247).

Achieving code execution from arbitrary file read is dependent on the context. Some potentially interesting files for attackers could be:
* SSH keys
* /etc/passwd, /etc/shadow
* Project secrets and credentials (refer to Jenkins' [advisory](https://www.jenkins.io/security/advisory/2024-01-24/) for more information)
* Source code, build artifacts
* and more… 

### Binary Files Reading Limitations 
When a file is read, the process's default character encoding is used, which is UTF-8 for most deployments. Because of this, any invalid UTF-8 sequence (statistically almost 50% of all bytes, assuming an equal distribution) would be replaced by the sequence `0xef 0xbf 0xbd` and cause data loss.
Some other encodings (such as Windows-1252, commonly used by instances running on Windows) would make it more feasible to exfiltrate binary data.

# CSWSH Vulnerability (CVE-2024-23898)
As mentioned earlier, one of the ways to invoke the [Jenkins-CLI](https://www.jenkins.io/doc/book/managing/cli/) commands is by web sockets (which is the implementation of `jenkins-cli.jar`).

It is known that browsers don’t enforce SOP and CORS policies on WebSockets: “Cross-origin restrictions imposed by SOP and CORS policies do not apply to WebSockets because those restrictions are placed on HTTP responses while WebSockets work over WS(WebSocket) or WSS(WebSocketSecure) protocols.” ([source](https://dev.to/pssingh21/websockets-bypassing-sop-cors-5ajm)).



Since there is no Jenkins-crumb (CSRF token) nor Origin header check in the web sockets requests, any website can use [WebSockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) to invoke Jenkins-CLI commands with the victim's identity, in a similar fashion to CSRF vulnerabilities.

# Patch
The Jenkins security team patched CVE-2024-23897 by adding a secure configuration, which disables the “[expandAtFiles](https://github.com/kohsuke/args4j/blob/fc458a24d6bd08b58fdd0bd7e37acb08200eac59/args4j/src/org/kohsuke/args4j/CmdLineParser.java#L478)” feature.

```diff
+  public static boolean ALLOW_AT_SYNTAX = SystemProperties.getBoolean(CLICommand.class.getName() + ".allowAtSyntax");
//...
-    return new CmdLineParser(this);
+    ParserProperties properties = ParserProperties.defaults().withAtSyntax(ALLOW_AT_SYNTAX);
+    return new CmdLineParser(this, properties);
```
And CVE-2024-23898 was patched by adding an origin verification to the WebSocket endpoint (The `ALLOW` parameter serves as a toggle, granting administrators the ability to override the updated default behavior. Giving the option to consistently permit or deny access to the WS CLI, irrespective of the Origin):
```diff
public HttpResponse doWs(StaplerRequest req) {
    if (!WebSockets.isSupported()) {
        return HttpResponses.notFound();
    }
+    if (ALLOW == null) {
+        final String actualOrigin = req.getHeader("Origin");
+        final String expectedOrigin = StringUtils.removeEnd(StringUtils.removeEnd(+Jenkins.get().getRootUrlFromRequest(), "/"), req.getContextPath());
+
+        if (actualOrigin == null || !actualOrigin.equals(expectedOrigin)) {
+            LOGGER.log(Level.FINE, () -> "Rejecting origin: " + actualOrigin + "; expected was from request: " + +expectedOrigin);
+            return HttpResponses.forbidden();
+        }
+    } else if (!ALLOW) {
+        return HttpResponses.forbidden();
+    }
    Authentication authentication = Jenkins.getAuthentication2();

```

# Timeline
| Date    | Action |
| -------- | ------- |
| 2023/11/13 | We reported all issues to the Jenkins Security team |
| 2023/11/13 | Maintainers acknowledged the report |
| 2023/11/24 | Maintainers confirmed the issues |
| 2023/12/12 | We helped the vendor verify the fix |
| 2024/01/10 | Maintainers updated us on other attack scenarios and the classification of Critical and High for our findings |
| 2024/01/24 | Maintainers assigned CVEs, and released [advisory](https://www.jenkins.io/security/advisory/2024-01-24/) and patch versions 2.442, and LTS 2.426.3. |

# Summary
In this blog, we uncovered two vulnerabilities on Jenkins, the first one leverages the “[expandAtFiles](https://github.com/kohsuke/args4j/blob/fc458a24d6bd08b58fdd0bd7e37acb08200eac59/args4j/src/org/kohsuke/args4j/CmdLineParser.java#L479)” functionality to read arbitrary files and eventually execute arbitrary code on the server. The second finding has the potential to execute arbitrary commands as the victim, by manipulating them to visit a malicious link.

At Sonar, we emphasize the importance of Clean Code principles. Doing so creates software characterized by clarity, maintainability, and comprehensibility. These attributes not only help the identification and resolution of vulnerabilities throughout the development process but also lower the likelihood of introducing security weaknesses that malicious actors might exploit.

Lastly, we would like to give huge kudos to the Jenkins team, who quickly and professionally assessed our findings, maintained great communication throughout the disclosure process, and provided a comprehensive fix. Thank you!