---
title: "Securing GitHub Actions With SonarQube: Real-World Examples"
date: 2025-10-14
tags:
	- "github actions"
	- "command injection"
	- "code execution"
	- "supply chain"
advisory: false
origin: https://www.sonarsource.com/blog/securing-github-actions-with-sonarqube-real-world-examples/
cves: 
	- "CVE-2025-61584"
	- "CVE-2025-53637"
ghsas:
	- "GHSA-9g7x-737f-5xpc"
	- "GHSA-6mwm-v2vv-pp96"
---

The automation and convenience offered by GitHub Actions have made them an indispensable part of modern software development workflows. These powerful tools, however, are not immune to security vulnerabilities. At Sonar, we're excited to introduce you to our enhanced GitHub Actions analysis capabilities, designed to proactively identify and help developers remediate security weaknesses directly within their CI/CD pipelines.

By showcasing real-life examples of vulnerabilities SonarQube detected during our continuous scans of open-source projects, we will demonstrate the engine's capabilities and dive into the specific types of vulnerabilities that can arise in GitHub Actions and underscore their potential impact on your development environment and the security of your software supply chain. Understanding these risks is the first crucial step towards writing more secure and resilient GitHub Actions.

# Impact

A compromised GitHub Action can have severe, case-by-case impacts that depend on various factors such as the action's permissions, the secrets it accesses, and the scope of the repository it runs in. An attacker who injects malicious code into a workflow can execute arbitrary commands on the runner environment, potentially allowing them to steal credentials (like cloud keys or personal access tokens), or tamper with the build and deployment process, which is a significant supply chain risk for downstream users. 

Earlier this year, we saw an in-the-wild example in the [Nx "s1ngularity" incident](https://nx.dev/blog/s1ngularity-postmortem). In that specific case, a [vulnerability](https://nx.dev/blog/s1ngularity-postmortem#the-attack-chain) in an Nx GitHub Actions workflow allowed an attacker to perform command injection and steal the project's npm publishing token. This critical initial step enabled the attacker to publish malicious versions of the popular Nx packages to the official npm registry, which in turn infected thousands of downstream developers and organizations. The malware then proceeded to steal thousands of credentials.

In this blog, we will cover the common use cases of command injection and code execution vulnerabilities, with an additional interesting pitfall that developers might fall into. Some of the vulnerabilities we disclosed are redacted as they are yet to be fixed, but the public ones are tracked as: 

-   [serverless-dns GHSA-9g7x-737f-5xpc](https://github.com/serverless-dns/serverless-dns/security/advisories/GHSA-9g7x-737f-5xpc) fixed in [c5537dd](https://github.com/serverless-dns/serverless-dns/commit/c5537dd7f203c59f2b86d1e295c2371f3533946a) tracked as CVE-2025-61584

-   [meshtastic/firmware GHSA-6mwm-v2vv-pp96](https://github.com/meshtastic/firmware/security/advisories/GHSA-6mwm-v2vv-pp96) fixed in [e03f3de](https://github.com/meshtastic/firmware/commit/e03f3de185e8a67bd08e7af0c3425989e4b6e0ec) tracked as CVE-2025-53637

# Technical Details
## GitHub Actions background

GitHub Actions live inside your GitHub project and are defined in YAML files under the `.github/workflows` directory. Each workflow outlines one or more jobs, and each job contains a series of steps, specifying what actions to take, when to trigger them (e.g., on a code push or pull request), and the environment in which they should execute. Acting as the blueprint for your continuous integration, deployment, and other automation tasks, making it easy to understand and manage your automation logic directly alongside your code

Commonly, GitHub Actions are used as Continuous Integration and Continuous Delivery (CI/CD) pipelines, performing tasks such as automated builds, tests, deployments, and more. However, they are capable of doing whatever developers can script, as they essentially provide a full containerized environment.

But as with every technology, there are some risks involved; if not used safely, attackers might exploit vulnerable workflows and potentially lead to a devastating impact for their victims. GitHub does emphasize the importance of security and best practices when writing workflows; they provide [official documentation and explanations](https://docs.github.com/en/actions/security-for-github-actions) on the topic. Despite their best efforts, developers might still make mistakes. This is where SonarQube comes in. With our new analyzer, we started supporting static scanning of your GitHub actions, and the best part is that it's completely free for open-source projects!

## Command injection
Let's dive into the details, starting with a straightforward case. SonarQube reported a command injection vulnerability in the following workflow:
```yaml
name: <redacted>
on:
  push:
    branches:
      - master
  pull_request_target:
    types: [opened, edited, reopened, closed]
  issues:
    types: [opened, edited]
jobs:
  <redacted>:
    runs-on: ubuntu-latest
    name: <redacted>
    steps:
    - name: <redacted>
      if: ${{ github.event_name == 'issues' && github.event.action == 'opened' }}
      run: |
        MESSAGE="New issue ${{ github.event.issue.title }} ...
```
Here, when a new issue is created, the workflow is triggered. During its execution in the `run` command, the code interpolates the issue's title into the shell command line. Every GitHub user can open an issue in this public repository, so the variable `github.event.issue.title` should be treated as untrusted input. Because there is no sanitization and the string is simply interpolated into the command line, an attacker can create an issue with a command injection payload in the title that will then execute in the context of the action runner.\
As a rule of thumb, [GitHub recommends](https://docs.github.com/en/actions/concepts/security/script-injections) that every content field that ends with `body`, `default_branch`, `email`, `head_ref`, `label`, `message`, `name`, `page_name`, `ref`, and `title` should be treated as untrusted.

### pull_request_target Command injection - CVE-2025-53637

The second example is similar to the first finding; however, this is using the `pull_request_target` event trigger. From a security standpoint, the difference between `pull_request` and `pull_request_target` is crucial. Workflows triggered by `pull_request` run in the context of the pull request branch, having a limited read-only `GITHUB_TOKEN`. Conversely, workflows triggered by `pull_request_target` run against the base branch of the repository and can have write access to the repository's contents and secrets via the `GITHUB_TOKEN`.  This elevated permission level means that a successful exploit using a `pull_request_target` workflow can lead to a severe supply chain compromise, potentially allowing an attacker to modify the repository's code, publish releases, or steal secrets, even from an untrusted contributor's pull request. The severity of this risk, however, is highly dependent on the repository's configuration, specifically the branch protection rules on the base branch and the explicit permissions defined for the workflow's `GITHUB_TOKEN`.

<img src="/img/blogs/GitHub-actions/image2.png" style="width: 100%;"/>

Try it yourself in [SonarQube Cloud](https://sonarcloud.io/project/issues?impactSoftwareQualities=SECURITY&issueStatuses=OPEN%2CCONFIRMED&id=SonarSourceResearch_github-actions-blogpost&open=AZnJQ6iMRifC2IfrVD7h)

This finding showcases a straightforward vulnerability as the `github.head_ref` is taken from the untrusted branch name, which can contain a command injection payload. Following our report, the downstream project has [fixed](https://github.com/meshtastic/firmware/commit/e03f3de185e8a67bd08e7af0c3425989e4b6e0ec) the issue using the official best practices mitigation.

## Command injection mitigation

When looking at the [official best practices for mitigating command injections](https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks), GitHub recommends adding the untrusted fields into an environment variable and then using that in the command line. This will prevent the untrusted data from being interpreted as executable code by the shell, as the contents of the environment variable are typically passed as a single argument or value:
```yaml
jobs:
  safe-echo-body:
    runs-on: ubuntu-latest
    steps:
    -  env:
        BODY: ${{ github.event.issue.body }}
      run: |
        echo "$BODY"
```

## Command injection mitigation pitfall - CVE-2025-61584

Despite the comprehensive explanations given by GitHub, there is an interesting pitfall that developers might fall into. Especially when this pitfall is given as an [example by GitHub in their official documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-variables#using-the-env-context-to-access-environment-variable-values), not when using untrusted input:

<img src="/img/blogs/GitHub-actions/image1.png" style="width: 100%;"/>

Did you notice the subtle difference?

The environment variables in the second example are used in the `run` command line as such: `run: echo "${{ env.First_Name }}"` instead of `run: echo "$First_Name"`. While in this case the First_Name environment variable isn't controlled by an untrusted user, the interpolation here is performed in an unsafe manner because it uses GitHub Actions' context and expression syntax (`${{ ...}}`) to insert the environment variable's value **before** the job is sent to the runner's shell for execution. This bypasses the shell's built-in defense mechanism that typically handles environment variables, meaning that if this environment variable were user-controlled, this would have been a valid vulnerability.

And to demonstrate this, SonarQube detected such a vulnerability in [serverless-dns](https://github.com/serverless-dns/serverless-dns):

<img src="/img/blogs/GitHub-actions/image3.png" style="width: 100%;"/>

Try it yourself in [SonarQube Cloud](https://sonarcloud.io/project/issues?impactSoftwareQualities=SECURITY&issueStatuses=OPEN%2CCONFIRMED&id=SonarSourceResearch_github-actions-blogpost&open=AZnJQ6fARifC2IfrVD7e)

This was [fixed](https://github.com/serverless-dns/serverless-dns/commit/c5537dd7f203c59f2b86d1e295c2371f3533946a) following our report using the environment variable safely.

## Code execution

The final major vulnerability we will cover is **Code Execution** within GitHub Actions workflows. Unlike the direct and easily identifiable signs of **Command Injection** (e.g., untrusted input in a shell command), this vulnerability is often harder to detect as it relies on ambiguous commands, or third-party Actions being executed on user-controlled code.

Consider the following workflow example with the SonarQube report, taken from an undisclosed project:
```yaml
name: <redacted>
on:
  pull_request_target:
    types:
      - opened
      - edited
      - synchronize
      - labeled
      - unlabeled

jobs:
  <redacted>:
    runs-on: ubuntu-22.04
    permissions:
      contents: write
    steps:
# ...
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          ref: ${{github.event.pull_request.head.ref}}
          repository: ${{github.event.pull_request.head.repo.full_name}}
# ...
      - name: Generate manpage
        uses: actions-rs/cargo@v1
        with:
          command: run
# ...
```
<img src="/img/blogs/GitHub-actions/image4.png" style="width: 100%;"/>
While there is no obvious command injection flaw, the combination of three critical steps creates a high-severity vulnerability:

1.  The `pull_request_target` trigger and elevated permissions - The workflow is triggered by the `pull_request_target` event. As previously discussed, this event is designed to run in the context of the base branch (the repository where the workflow resides), not the untrusted head branch.

2.  But more crucially, the workflow checks out the untrusted code - By explicitly setting repository and ref to point to `github.event.pull_request.head.repo.full_name`, and ``github.event.pull_request.head.ref``, it checks out the full, untrusted code from the contributor's repository (the head branch) into the runner's working directory.

3.  The job then proceeds to execute a third-party Action, [actions-rs/cargo@v1](https://github.com/actions-rs/cargo), with the command `run`. This will execute Rust's [cargo](https://doc.rust-lang.org/cargo/)  [run](https://doc.rust-lang.org/cargo/commands/cargo-run.html) command, which simply runs the current package. Since the "package" code is fully user-controlled, an attacker can write arbitrary Rust code that will then be executed

This case is a clear example of checkout code being executed. However, many times developers may not be aware of what the third-party GitHub Actions are actually doing behind the scenes. The hidden nature of this type of vulnerability makes it a far more insidious and challenging supply chain risk than traditional command injection. Because developers often trust the actions they import from the GitHub Marketplace or verified vendors, they may not scrutinize what those actions do when pointed at untrusted, user-controlled code.

# Timeline
| Date    | Action |
| -------- | ------- |
| 2025-04-15 | We report all issues to various vendors |
| 2025-04-16 | meshtastic/firmware confirms the issues |
| 2025-04-19 | serverless-dns confirms the issues |
| 2025-04-20 | meshtastic/firmware releases [patch](https://github.com/meshtastic/firmware/commit/e03f3de185e8a67bd08e7af0c3425989e4b6e0ec) |
| 2025-04-26 | serverless-dns releases [patch](https://github.com/serverless-dns/serverless-dns/commit/c5537dd7f203c59f2b86d1e295c2371f3533946a) |
| 2025-06-10 | meshtastic/firmware publishes [GHSA-6mwm-v2vv-pp96](https://github.com/meshtastic/firmware/security/advisories/GHSA-6mwm-v2vv-pp96) advisory |
| 2025-09-29 | serverless-dns publishes [GHSA-9g7x-737f-5xpc](https://github.com/serverless-dns/serverless-dns/security/advisories/GHSA-9g7x-737f-5xpc) advisory |

# Summary

This blog post highlights the critical security risks inherent in using GitHub Actions and introduces SonarQube's enhanced analysis capabilities designed to detect and help remediate these vulnerabilities directly within CI/CD pipelines. We took a closer look at the technical details of some vulnerabilities and showcased the power of SonarQube by using real-world examples of vulnerabilities we found with it.

A compromised action can lead to severe consequences, including the theft of credentials and the potential for a full-scale software supply chain attack, as demonstrated by the high-profile Nx "s1ngularity" incident, where a vulnerability allowed command injection and the theft of an npm publishing token. Understanding these risks is essential for developers.