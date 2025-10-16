---
title: "Securing Go Applications With SonarQube: Real-World Examples"
date: 2025-08-07
tags:
	- "go"
	- "arbitrary file write"
	- "rce"
	- "xss"
advisory: false
origin: https://www.sonarsource.com/blog/securing-go-applications-with-sonarqube-real-world-examples/
cves: 
	- "CVE-2025-56760"
	- "CVE-2025-56761"
---
[Go](https://go.dev/) has become a language of choice for modern backend development, and its adoption in cloud-native and microservices architectures is growing rapidly. As Go's use grows, so does the demand for specialized security tools. That's why we at Sonar have enhanced our powerful static analysis engine to provide advanced security scanning for Go code.

Driven by our dedication to both open-source security and the advancement of our technology, we leverage the power of [SonarQube Cloud](https://www.sonarsource.com/products/sonarcloud/) to scan and identify potential vulnerabilities in popular open-source projects proactively. With the new Go analysis within our continuous scanning, we will demonstrate how SonarQube Cloud reports vulnerabilities in Go and take a deep dive into the technical details and impact of our findings.

# Gin
-----

[Gin](https://github.com/gin-gonic/gin) is one of the most popular web frameworks in Go. It features a fast and simple API, and according to the maintainers, its performance can be up to 40 times faster than other frameworks. With over 83k stars on GitHub, it's a huge part of the Go ecosystem. However, even the most widely used tools can have their weak spots. A vulnerability report from SonarQube Cloud pointed out a risk related to not enforcing TLS 1.2 or above. Let's take a closer look at this security concern and how to address it ([RSPEC-4423](https://rules.sonarsource.com/go/type/Vulnerability/RSPEC-4423/)):

<img src="/img/blogs/memos/image2.png" style="width: 100%;"/>

[Try it yourself on SonarQube Cloud](https://sonarcloud.io/project/issues?impactSoftwareQualities=SECURITY&issueStatuses=OPEN%2CCONFIRMED&id=SonarSourceResearch_gin-blogpost&open=AZh-iThIQHa9mx1tR-Fu)

Gin under the hood relies on Go's standard `net/http` package to run its server. This is also the case when serving content over TLS, which is handled by the [RunTLS](https://github.com/gin-gonic/gin/blob/v1.10.0/gin.go#L509) function:

```go
func (engine *Engine) RunTLS(addr, certFile, keyFile string) (err error) {
	debugPrint("Listening and serving HTTPS on %s\n", addr)
	defer func() { debugPrintError(err) }()
	if engine.isUnsafeTrustedProxies() {
		// ...
	}
	err = http.ListenAndServeTLS(addr, certFile, keyFile, engine.Handler())

	return
}
```

The issue here lies with Go versions prior to 1.22. The `http.ListenAndServeTLS` function in those versions doesn't automatically enforce a secure TLS configuration. By default, it accepts connections using **TLS 1.0 and 1.1**, both of which are now considered insecure and deprecated. This leaves applications using Gin in such a configuration vulnerable to well-known attacks like [BREACH](https://en.wikipedia.org/wiki/BREACH)  and  [BEAST](https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack), which can compromise the confidentiality of the connection and lead to data theft.

### Patch

The Gin maintainers addressed this vulnerability in [version 1.10.1](https://github.com/gin-gonic/gin/releases/tag/v1.10.1) ([b5af779](https://github.com/gin-gonic/gin/commit/b5af7796535d97d9c7af42539af01d787fcb3b4d)). They patched the issue by configuring the server to use a minimum TLS version of 1.2. The fix was implemented by setting `MinVersion: tls.VersionTLS12` in the server's configuration, ensuring that all connections meet modern security standards.

# Memos
-----

[Memos](https://github.com/usememos/memos) stands out as a lightweight, open-source note-taking application that embraces simplicity. Built with Go and React, it is designed for seamless deployment and cross-platform accessibility. Memos allows users to effortlessly capture and organize their thoughts, ideas, and to-dos. Its straightforward design and self-hosting capabilities have resonated with many, which is evident by its impressive 40k+ stars on GitHub.

However, our recent security research has uncovered a serious issue. We've identified two critical vulnerabilities that, when chained together, could allow a low-privileged authenticated attacker to take complete control of a Memos server.

These vulnerabilities are:

1.  **CVE-2025-56761, Stored Cross-Site Scripting (XSS)**: We also discovered two stored XSS vulnerabilities. Allowing attackers to inject JavaScript code that, when executed by an administrator, could abuse the admin's privileges. This, in turn, could be used to update the instance configuration, allowing exploitation of the second Path Traversal vulnerability for a full server compromise.

2.  **CVE-2025-56760, Arbitrary File Write via Path Traversal**: When Memos is configured to use [local storage](https://www.usememos.com/docs/advanced-settings/local-storage), a flaw in how it handles file paths allows an authenticated attacker to write arbitrary files to the server. This could be leveraged to achieve full remote code execution, giving them full control of the system.

Despite our best efforts to responsibly disclose and contact the maintainers, we unfortunately did not receive a response. In accordance with our 90-day disclosure policy, we are now making this information public to ensure user awareness. We strongly recommend that individuals and organizations deploying Memos be acutely aware and take immediate action. The most secure course is to **restrict Memos access to trusted users only**. This could help mitigate the immediate risks, but the long-term solution requires a patch from the maintainers or a transition to a more secure platform.

### Technical Details

#### Path Traversal Vulnerability (CVE-2025-56760)

The core of this issue lies in the [/memos.api.v1.ResourceService/CreateResource](https://github.com/usememos/memos/blob/v0.24.0/server/router/api/v1/resource_service.go#L47) endpoint, which handles file uploads. While the function correctly checks if a user is authenticated, it doesn't perform any further authorization checks. This means that *any* authenticated user, regardless of their role or privileges, can initiate a file upload.

```go
user, err := s.GetCurrentUser(ctx)
if err != nil {
	return nil, status.Errorf(codes.Internal, "failed to get current user: %v", err)
}
```
The function then constructs a `Resource` object with the `Filename`, `Type`, and `Blob` fully taken from the request and calls the [SaveResourceBlob](https://github.com/usememos/memos/blob/v0.24.0/server/router/api/v1/resource_service.go#L286) function:
```go
//...
create := &store.Resource{
	UID:       shortuuid.New(),
	CreatorID: user.ID,
	Filename:  request.Resource.Filename,
	Type:      request.Resource.Type,
}

//...

create.Size = int64(size)
create.Blob = request.Resource.Content
if err := SaveResourceBlob(ctx, s.Store, create); err != nil {
	return nil, status.Errorf(codes.Internal, "failed to save resource blob: %v", err)
}
```

The vulnerability exists within the `SaveResourceBlob` function. We can see that one of the user-controlled inputs is passed into a `filepathTemplate`, which is then used to create a file. 

```go
func SaveResourceBlob(ctx context.Context, s *store.Store, create *store.Resource) error {
	workspaceStorageSetting, err := s.GetWorkspaceStorageSetting(ctx)
	if err != nil {
		return errors.Wrap(err, "Failed to find workspace storage setting")
	}

	if workspaceStorageSetting.StorageType == storepb.WorkspaceStorageSetting_LOCAL {
		filepathTemplate := "assets/{timestamp}_{filename}"
		if workspaceStorageSetting.FilepathTemplate != "" {
			filepathTemplate = workspaceStorageSetting.FilepathTemplate
		}

		internalPath := filepathTemplate
		if !strings.Contains(internalPath, "{filename}") {
			internalPath = filepath.Join(internalPath, "{filename}")
		}
		internalPath = replaceFilenameWithPathTemplate(internalPath, create.Filename)
		internalPath = filepath.ToSlash(internalPath)
		osPath := filepath.FromSlash(internalPath)

		//...

		// Write the blob to the file.
		if err := os.WriteFile(osPath, create.Blob, 0644); err != nil {
			return errors.Wrap(err, "Failed to write file")
		}
		//...
```
However, there is a small if condition before going into the vulnerable path. This is where the prerequisite of this vulnerability takes place. But what is `workspaceStorageSetting`, and when is it equal to `WorkspaceStorageSetting_LOCAL`? 
For privacy reasons, memos provides a feature to store objects locally instead of in a database or S3.

<img src="/img/blogs/memos/image1.png" style="width: 100%;"/>

When a user uploads a file on a Memos instance using this configuration, it will be saved under the `bin/memos/assets` folder using the default `{timestamp}_{filename}` filename template. While this is configurable in the settings, the only field that is fully user-controlled is `{filename}`. This is in the template by default and is replaced in the function [replaceFilenameWithPathTemplate](https://github.com/usememos/memos/blob/v0.24.0/server/router/api/v1/resource_service.go#L441). 

An authenticated attacker can leverage this to create a resource with a filename containing a path traversal sequence `../` and traverse back from the intended `assets` folder. Since the file's content is also controlled by the attacker, this grants a powerful arbitrary file write primitive.

The severity of this flaw is significant. It could lead to remote code execution by allowing an attacker to write files that the server executes, such as cron jobs or malicious scripts. They could also overwrite crucial application configurations or modify SSH keys for a full server compromise.

#### Stored Cross-Site Scripting (XSS) Vulnerability (CVE-2025-56761)

But what if the `workspaceStorageSetting` isn't configured to store files locally? In this case, an attacker can use the built-in feature to share files. Since the user-controlled files are served under the same domain without any restriction/sandboxing.

When the administrator views this file, the XSS payload executes, potentially allowing the attacker to steal the admin's session or escalate their privileges. With administrative access, the attacker can then change the `workspaceStorageSetting` to `LOCAL`, opening the door to the Path Traversal vulnerability and leading to a full server compromise.

<img src="/img/blogs/memos/image3.png" style="width: 100%;"/>

Furthermore, we found another path for XSS through the user avatar functionality. When a user updates their avatar via the [UpdateUser](https://github.com/usememos/memos/blob/v0.24.0/server/router/api/v1/user_service.go#L147) endpoint, Memos accepts a `data:` URL.

```go
func (s *APIV1Service) UpdateUser(ctx context.Context, request *v1pb.UpdateUserRequest) (*v1pb.User, error) {
	//...
	update := &store.UpdateUser{
		ID:        user.ID,
		UpdatedTs: &currentTs,
	}
	for _, field := range request.UpdateMask.Paths {
		//...
		} else if field == "avatar_url" {
			update.AvatarURL = &request.User.AvatarUrl
	updatedUser, err := s.Store.UpdateUser(ctx, update)
```

When the avatar is later requested, Memos serves its content via the [GetUserAvatarBinary](https://github.com/usememos/memos/blob/v0.24.0/server/router/api/v1/user_service.go#L110) function:

```go
func (s *APIV1Service) GetUserAvatarBinary(ctx context.Context, request *v1pb.GetUserAvatarBinaryRequest) (*httpbody.HttpBody, error) {
	//...
	user, err := s.Store.GetUser(ctx, &store.FindUser{
		ID: &userID,
	})
	//...
	imageType, base64Data, err := extractImageInfo(user.AvatarURL)
	//...
	imageData, err := base64.StdEncoding.DecodeString(base64Data)
	//...
	httpBody := &httpbody.HttpBody{
		ContentType: imageType,
		Data:        imageData,
	}
	return httpBody, nil
}
```

Which extracts the image data using [extractImageInfo](https://github.com/usememos/memos/blob/v0.24.0/server/router/api/v1/user_service.go#L581) function. By parsing the provided `data` URL, Memos extracts both the content and the `content-type` provided by the user.

```go
func extractImageInfo(dataURI string) (string, string, error) {
	dataURIRegex := regexp.MustCompile(`^data:(?P<type>.+);base64,(?P<base64>.+)`)
	matches := dataURIRegex.FindStringSubmatch(dataURI)
	if len(matches) != 3 {
		return "", "", errors.New("Invalid data URI format")
	}
	imageType := matches[1]
	base64Data := matches[2]
	return imageType, base64Data, nil
}
```

Since the application doesn't validate that the content is a legitimate image, an attacker can specify a `text/html` content type and embed a malicious script. This script will execute when the avatar is displayed to other users, creating another avenue for Stored XSS.

### Patch

Despite our best efforts to responsibly disclose and contact the maintainers, we unfortunately did not receive a response. In accordance with our 90-day disclosure policy, we are now making this information public to ensure user awareness. We strongly recommend that individuals and organizations deploying Memos be acutely aware and take immediate action. The most secure course is to **restrict Memos access to trusted users only**. This could help mitigate the immediate risks, but the long-term solution requires a patch from the maintainers or a transition to a more secure platform.

# Timeline

| Date    | Action |
| -------- | ------- |
| 2025-02-11 | We report all issues to Memos |
| 2025-03-13 | We ping Memos, mentioning that 30 days have passed |
| 2025-03-17 | We report our findings to Gin |
| 2025-04-11 | We ping Memos, mentioning that 60 days have passed |
| 2025-05-07 | We open a security advisory on GitHub |
| 2025-05-19 | We ping Gin’s maintainers  |
| 2025-05-20 | Gin’s maintainers acknowledge our report and fix the issue |
| 2025-05-12 | We notify Memos that our 90-day disclosure window has elapsed and that we will be releasing the information to the public |
| 2025-09-02 | CVEs CVE-2025-56760 and CVE-2025-56761 are assigned |

# Summary
Our security research into popular Go projects has revealed critical vulnerabilities that highlight the continuous importance of rigorous security analysis in open-source projects. Leveraging the power of SonarQube's static analysis capabilities, developers can easily detect and mitigate such vulnerabilities during the development process. This proactive approach is crucial, as even the most widely used and trusted tools can contain hidden flaws.

In the case of the Gin framework, we identified a weakness in its default configuration for serving TLS. This issue, while now patched by the maintainers, serves as a powerful reminder that even foundational components require careful scrutiny to prevent exposure to known cryptographic attacks.

Meanwhile, our investigation into the Memos uncovered a more severe threat landscape. We found critical vulnerabilities that could allow an authenticated attacker to achieve full server compromise. Despite our attempts to responsibly disclose these findings to the maintainers, we did not receive a response. In accordance with our disclosure policy, we are making this information public to ensure that users are aware of the risks.


