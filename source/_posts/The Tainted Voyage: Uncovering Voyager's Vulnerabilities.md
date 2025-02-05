---
title: "The Tainted Voyage: Uncovering Voyager's Vulnerabilities"
date: 2025-01-27
tags:
    - "xss"
    - "polyglot"
    - "rce"
    - "file-upload"
advisory: false
origin: https://www.sonarsource.com/blog/the-tainted-voyage-uncovering-voyagers-vulnerabilities/
cves:
    - "CVE-2024-55417"
    - "CVE-2024-55416"
    - "CVE-2024-55415"
---
[Voyager](https://voyager.devdojo.com/ "Voyager") is a popular open-source PHP package designed to streamline the management of Laravel applications. It provides a pre-built, user-friendly admin interface and offers a range of features, such as BREAD operations, media management, user management, and more. With over 11,000 GitHub stars and millions of downloads, it has established itself as a reliable and widely-used solution in the Laravel community.

By leveraging SonarQube Cloud's code analysis, which is free to use for open-source projects, we continuously and proactively identify and mitigate risks within open-source projects, benefiting both the community and our own tools. During one of many scans we performed, a Voyager finding caught our eye, which led us to a further audit of the project and eventually discover and disclose critical vulnerabilities in the project.

# Key Information
-   During our continuous scans, SonarQube Cloud [reported](https://sonarcloud.io/project/issues?issueStatuses=OPEN%2CCONFIRMED&types=VULNERABILITY&id=SonarSourceResearch_voyager-blogpost&open=AZNs69Z-Bb89eYtXmCnW "reported") an arbitrary file write vulnerability in Voyager.
-   After further research of the project, we discovered additional vulnerabilities and combined them to create a realistic attack scenario, which resulted in one-click remote code execution on a Voyager instance.
-   We reported the findings to the project maintainers multiple times via emails and Github with no reply.
-   We release this information to the public in order to protect users, under our 90-day responsible disclosure policy.

# Impact
When an authenticated Voyager user clicks on a malicious link, attackers can execute arbitrary code on the server. **At the time of writing this blog (Voyager version 1.8.0), the vulnerabilities have not been fixed** and we release this information to allow users to protect themselves under our 90-day responsible disclosure deadline.

<iframe width="736" height="414" src="https://www.youtube.com/embed/qLCrPCXEcec" title="The Tainted Voyage: Uncovering Voyager&#39;s Vulnerabilities" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

# Technical Details
## Background
Let’s take a look at the report that caught our attention.

<img src="/img/blogs/voyager/sonarqube.png" style="width: 100%;"/>

*Try it yourself on *[*SonarQube Cloud*](https://sonarcloud.io/project/issues?issueStatuses=OPEN%2CCONFIRMED&types=VULNERABILITY&id=SonarSourceResearch_voyager-blogpost&open=AZNs69Z-Bb89eYtXmCnW "see it yourself on SonarQube Cloud")*.*

Initially, the issue appeared to be a straightforward path traversal vulnerability within the application's media upload component. However, a deeper analysis revealed limitations an attacker would need to overcome in order to make this vulnerability impactful. Expanding the truncated part from the sink (user input) to the source (the dangerous `storeAs` function) shows interesting information:

```php
public function upload(Request $request)
{
    // Check permission
    $this->authorize('browse_media');

    $extension = $request->file->getClientOriginalExtension();
    $name = Str::replaceLast('.'.$extension, '', $request->file->getClientOriginalName());
    $details = json_decode($request->get('details') ?? '{}');
    $absolute_path = Storage::disk($this->filesystem)->path($request->upload_path);

    try {
        $realPath = Storage::disk($this->filesystem)->path('/');

        $allowedMimeTypes = config('voyager.media.allowed_mimetypes', '*');
        if ($allowedMimeTypes != '*' && (is_array($allowedMimeTypes) && !in_array($request->file->getMimeType(), $allowedMimeTypes))) {
            throw new Exception(__('voyager::generic.mimetype_not_allowed'));
        }

        //...
        $file = $request->file->storeAs($request->upload_path, $name.'.'.$extension, $this->filesystem);
```
There are two important checks here, which are performed before the file is saved to the disk. 

1.  The first one verifies that the user who made the request has the `browse_media` permission, which means that no ordinary user can execute this action. 
2.  The second one verifies if the file's [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/MIME_types "MIME type") is allowed (predefined in the configuration).

Can you think of ways an attacker would try to bypass these when crafting an exploit? We will deep-dive into each point using different vulnerabilities, starting with the second one, the mime-type verification.

## Arbitrary File Write vulnerability (CVE-2024-55417)

When a file is uploaded to the `/admin/media/upload` endpoint, Voyager [checks](https://github.com/thedevdojo/voyager/blob/1.7/src/Http/Controllers/VoyagerMediaController.php#L238 "checks") the request file's MIME type via Laravel's (which uses Symphony) [getMimeType](https://laravel.com/api/master/Illuminate/Support/Facades/Request.html#method_getMimeType "getMimeType") function. In order to understand how it works, let's take a look at a similar function's [documentation](https://github.com/symfony/symfony/blob/73d490466bdaf09fb5ee57ea55a91db40f8c6b03/src/Symfony/Component/HttpFoundation/File/UploadedFile.php#L126 "documentation"), `getClientMimeType:`

> The client mime type is extracted from the request from which the file was uploaded, so it should not be considered as a safe value. For a trusted mime type, use getMimeType() instead (which guesses the mime type based on the file content).

When a user uploads a file (via form data), they provide a file name and content type in addition to the file's content. While some functions get the type of the file from the name's extension or the content type, getMimeType is supposed to be "safer" by [sniffing](https://en.wikipedia.org/wiki/Content_sniffing "sniffing")/guessing it from the content itself.

After sniffing the MIME type, the [VoyagerMediaController@upload](https://github.com/thedevdojo/voyager/blob/1.6/src/Http/Controllers/VoyagerMediaController.php#L238 "VoyagerMediaController@upload") function crosses it with a predefined list and [throws an exception](https://github.com/thedevdojo/voyager/blob/1.6/src/Http/Controllers/VoyagerMediaController.php#L239 "throws an exception") when not allowed.

```php
if ($allowedMimeTypes != '*' && (is_array($allowedMimeTypes) && !in_array($request->file->getMimeType(), $allowedMimeTypes))) {
  throw new Exception(__('voyager::generic.mimetype_not_allowed'));
}
```

The [default](https://github.com/thedevdojo/voyager/blob/873bce194e3066b89ac2e46d6063179b35c6f52d/publishable/config/voyager.php#L227-L233 "default") `allowedMimeTypes` list contains harmless content types:

-   image/jpeg
-   image/png
-   image/gif
-   image/bmp
-   video/mp4

But file formats can be complicated. While some types of files have a clear and strict structure, others might be less obvious. For example, a PHP-based file doesn't require to start with a specific order of bytes ([file header](https://en.wikipedia.org/wiki/List_of_file_signatures "file header")) to be valid. Consequently, if a file contains the PHP opening tag `<?php` anywhere within its content, the embedded PHP code can be executed by a PHP interpreter.

Therefore, if an attacker can manipulate the content type sniffing mechanism to classify a malicious file as an allowed file type and subsequently induce the server to process it as a PHP script, this arbitrary file write vulnerability could be escalated into a critical remote code execution by uploading a web shell.

### Introducing Polyglot Files: A Double-Edged Sword
[Polyglot](https://en.wikipedia.org/wiki/Polyglot_(disambiguation) "Polyglot") files are files that can be interpreted as multiple file types, taking advantage of the flexibility and variety of file formats. While this flexibility can be beneficial in some cases, it can also be exploited by malicious actors.

In the context of this vulnerability, an attacker could craft a polyglot file that appears to be a legitimate file type to the `getMimeType` function (e.g., an image or video) but actually contains malicious PHP code.\
However, in order for the malicious code to be executed, the server should serve and render the file as PHP, which is determined by the extension. Since the upload mechanism doesn't implement any file extension verification, an attacker can simply decide on an arbitrary extension. Resulting in arbitrary code execution by users who have the `browse_media` permissions.

<img src="/img/blogs/voyager/webshell.png" style="width: 100%;"/>

## Reflected Cross-Site Scripting (CVE-2024-55416)

While the arbitrary file upload vulnerability, coupled with PHP's permissive nature, could lead to remote code execution, its impact is currently limited by the `browse_media` permission requirement. As Voyager is primarily targeted at administrators, this limitation reduces the immediate severity of the issue. The main concern lies in the potential for unauthorized code execution within the administrative context. While this might be a significant issue for some applications, it's less critical in scenarios where all administrators are trusted.

To escalate this vulnerability to a critical threat, an attacker would need to combine it with another vulnerability, such as authorization bypass, cross-site request forgery (CSRF), or cross-site scripting (XSS) attack, to execute malicious code on behalf of a privileged user.

When auditing the rest of the Voyager codebase we noticed an interesting endpoint: the `/admin/compass` which gets handled by the [VoyagerCompassController@index](https://github.com/thedevdojo/voyager/blob/1.6/src/Http/Controllers/VoyagerCompassController.php#L19 "VoyagerCompassController@index") component, allowing the execution of certain actions via a GET request. Despite it still requiring admin permissions when handling GET requests, an attacker can craft a URL and manipulate an authenticated user to invoke the request by clicking on the link.

One of the actions that this endpoint provides is [deleting a file](https://github.com/thedevdojo/voyager/blob/1.6/src/Http/Controllers/VoyagerCompassController.php#L44 "deleting a file"). After the action is done (regardless of whether the file is found or deleted), a small popup will be displayed to the user in the UI.

```php
elseif ($this->request->has('del')) {
  $active_tab = 'logs';
  app('files')->delete(LogViewer::pathToLogFile(base64_decode($this->request->input('del'))));
  return redirect($this->request->url().'?logs=true')->with([
    'message'    => __('voyager::compass.logs.delete_success').' '.base64_decode($this->request->input('del')),
    'alert-type' => 'success',
  ]);
}
```

The issue here is that when Voyager [renders the popup](https://github.com/thedevdojo/voyager/blob/1.6/resources/assets/js/helpers.js#L52 "renders the popup") message, it contains the provided file name unsanitized:

```php
function notify(type, message) {
  let alert = '<div class="alert alert-'  + type +  dismissibleClass + '" role="alert">'  + dismissButton + message +  '</div>';
  $(options.alertsContainer).append(alert);
 }
```
This means that if an authenticated user clicks on a specially crafted link, arbitrary JavaScript code can be executed. As a result, an attacker can perform any subsequent action in the context of the victim. Combining it with the previous finding an attacker can escalate it to execute arbitrary code on the server 

<img src="/img/blogs/voyager/xss.png" style="width: 100%;"/>

## Arbitrary File Leak and Deletion (CVE-2024-55415)
If an attacker wants to be more stealthy and just steal or delete files without having to drop a malicious PHP file on disk, they could use the same endpoint to do so.

The user-provided path is sent to the [​pathToLogFile](https://github.com/thedevdojo/voyager/blob/1.6/src/Http/Controllers/VoyagerCompassController.php#L213 "​​pathToLogFile") function, but looking at the code, there isn't any normalization or modification of the input. The function only checks that the file exists:

```php
public static function pathToLogFile($file)
    {
        $logsPath = storage_path('logs');

        if (app('files')->exists($file)) { // try the absolute path
            return $file;
        }

        $file = $logsPath.'/'.$file;

        // check if requested file is really in the logs directory
        if (dirname($file) !== $logsPath) {
            throw new \Exception('No such log file');
        }

        return $file;
    } 
```
An attacker can initiate the deletion of arbitrary files by tricking a user into clicking a malicious link. As discussed in the previous finding, this vulnerability is triggered before sending the unsanitized message to the user.\
Arbitrary file deletion can have a severe impact on an application. The obvious one is impacting the availability of the server, but in some cases, we have seen [unique ways](https://www.sonarsource.com/blog/wordpress-file-delete-to-code-execution/ "unique ways") attackers used arbitrary file deletion to gain code execution (via configuration deletion, installation, etc)

Additionally, the `/admin/compass` endpoint is responsible for downloading a file. In this case, it doesn't directly expose sensitive information to the attacker because the file will be downloaded to the victim's machine. However, the previous XSS can be leveraged to get the content of the file via Javascript, and then send it to the attacker's controlled server.

# Patch
At this time, no patches are available to address the vulnerabilities we've identified. Despite multiple attempts to contact the project maintainers via email and GitHub, we have not received a response.

In accordance with our responsible disclosure policy, we are publicly releasing the details of our findings after 90 days. We believe this allows users of Voyage to make informed decisions about their use of Voyage.

We strongly advise users to carefully consider using this project in their applications and exercise caution when deciding to do so.


# Timeline
| Date    | Action |
| -------- | ------- |
| 2024-09-11 | We report all issues to the maintainers. |
| 2024-10-20 | We ping the maintainers. |
| 2024-11-11 | We ping the maintainers mentioning that 60 days have passed. |
| 2024-11-28 | We open a security report via GitHubWe open a security report via GitHub. |
| 2024-12-11 | We notify the maintainers that the 90-day disclosure window has elapsed and that we are planning to release the details to the public. |
| 2025-01-27 | We release this blog post. |

# Summary

In this blog post, we delved into a security vulnerability uncovered by SonarQube Cloud within the Voyager project. We highlighted how attackers can leverage this vulnerability in conjunction with other security weaknesses to execute malicious code on vulnerable systems. By leveraging SonarQube Cloud's advanced code analysis capabilities, organizations can proactively identify and address security vulnerabilities, such as those demonstrated in this post, before they reach production.

Unfortunately, despite our best efforts, we were unable to reach the maintainers to address these vulnerabilities. We hope that by sharing this information, we can raise awareness among Voyager users regarding the project's security aspect.