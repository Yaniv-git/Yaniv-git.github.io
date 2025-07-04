---
title: Playing Dominos with Moodle's Security (2/2)
date: 2023-08-29
tags:
	- "moodle"
	- "ato"
	- "account take over"
	- "oauth"
advisory: false
origin: https://www.sonarsource.com/blog/playing-dominos-with-moodles-security-2/
cves:
	- "CVE-2023-40320"
star: true
---
# Introduction
In our endeavor to enhance the security of the open-source realm and gain a deeper understanding of real-world vulnerabilities, we are constantly conducting audits of open-source projects, and the outcomes of this are presented in our two articles on Moodle security. This is the second blog covering another critical finding we discovered when auditing Moodle for security vulnerabilities. 

In the first blog, we demonstrated how an unauthorized attacker could turn an arbitrary folder creation into a Cross-Site Scripting (XSS) vulnerability, ultimately resulting in Remote Code Execution (RCE). The second part of the series follows the same line of starting with a considerably low-impact bug at first glance, but with some steps, attackers can leverage it to a full account takeover. 

# Impact
Moodle versions before 4.2.2, 4.1.5, 4.0.10, 3.11.16, and 3.9.23 are susceptible to Account Takeover (ATO) via self-XSS in the WYSIWYG editor – this is tracked as CVE-2023-40320. On Moodle instances where [OAuth](https://en.wikipedia.org/wiki/OAuth) authentication is enabled, victims' accounts can be compromised with a simple click on a link.

<iframe width="100%" height="414" src="https://www.youtube.com/embed/njeXbu85yzM" title="Demonstration of Moodle vulnerabilities (CVE-2023-40320) on a test instance" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

# Technical Details
In this section, we will discuss the technical details of the vulnerability and explain how attackers might exploit this kind of vulnerability.

## Background
A self-XSS vulnerability is when an attacker can execute arbitrary JavaScript code but the only one being affected by it is the attacker itself. To exploit this type of XSS, an attacker usually would need a high level of victim interaction, such as copying and pasting the payload to the vulnerable website. In many cases, this issue would not be considered a vulnerability, and even in the case of the Moodle vulnerability disclosure program, self-XSS is [out of scope](https://moodle.org/mod/page/view.php?id=8722#:~:text=Self%2DXSS%20(unless%20there%20is%20a%20proven%20impact%20on%20other%20users)) **“(unless there is a proven impact on other users).”**

# From Self-XSS to Account Takeover (CVE-2023-40320)
One of the initial steps we do when auditing an application is to use it as intended. Doing so helps us understand how it is supposed to behave and also brings many ideas to mind on how to manipulate the intended behavior the same way an attacker would. Pretty quickly we ran into the WYSIWYG editor in Moodle. 

Being one of the core features of Moodle, it appears when editing a description of a user, writing an answer to a forum, submitting assignments, and many more.

We noticed that there is the possibility to input arbitrary HTML which will be rendered and executed in the editor (making this a self-XSS). But when submitting the payload to a public page (such as a forum, assignment, etc.), it gets sanitized on the server side and dangerous elements are removed – other users will never be affected by the payload. 

<img src="/img/blogs/Moodle/image-2.webp" style="width: 100%;"/>

In addition, the editor has a feature that automatically saves a user's WYSIWYG content by sending the unsanitized data periodically after a couple of seconds to the `/lib/editor/atto/autosave-ajax.php` endpoint:

<img src="/img/blogs/Moodle/image-3.webp" style="width: 100%;"/>

When loading the page again, the autosaved data is fetched from the same endpoint using the `actions[0][action]` parameter set to `resume`. In case a malicious payload was stored before, it will execute again by visiting the WYSIWYG page – this just became a Stored Self-XSS!

# Exploitation strategies
One of the ways an attacker could leverage this type of bug to an impactful one is by manipulating a victim into logging in to a malicious account -> triggering the self-XSS -> raising the impact depending on the application. With it, this was the first exploitation idea we tested. After a small check, we saw that the login and logout features are CSRF-protected, meaning an attacker can’t log in or out on the victim’s behalf by manipulating them to visit a malicious website. 

In this case, an attacker needs to find some kind of “magic link” (a single link that logs in a user without a password, usually using a one-time token). The first idea we wanted to test is via an OAuth login. Yet again this endpoint was protected by a GET parameter `sesskey` which acts as a CSRF token. At this point, we decided that code auditing would yield better results than quick tests. 

Following the normal login procedure, the function that logs in a user is called `complete_user_login`. This function is called after the authentication is verified and would also log out the current user if there is one. Upon examining all the calls made to this function, we discovered several endpoints. However, we observed that they either verifying new accounts (Moodle accounts must be verified before users can access them, meaning an attacker can’t pre-deploy the self-XSS) or prohibited logging in if a session already existed. Changing the email of an existing account would send a confirmation message but the link provided only confirms and does not login, unlike the confirmation link when registering a new account.

# OAuth Authentication Flows
But then we came across `auth/oauth2/confirm-linkedlogin.php` 

```php
$token = required_param('token', PARAM_RAW);
$username = required_param('username', PARAM_USERNAME);
$userid = required_param('userid', PARAM_INT);
$issuerid = required_param('issuerid', PARAM_INT);
$redirect = optional_param('redirect', '', PARAM_LOCALURL);    // Where to 
//...
$confirmed = \auth_oauth2\api::confirm_link_login($userid, $username, $issuerid, $token);


if ($confirmed) {
//...
   if (!$user->suspended) {
       complete_user_login($user);
    //...
       if (!empty($redirect)) {
           redirect($redirect);
       }
//...
```

Here, if the link is valid, a login will happen. Without any verification that another user is already logged in, this is the only endpoint that does that. In addition to that, there is the possibility to pass a local `$redirect` URL that will redirect the user after the login!

But what is `oauth2/confirm-linkedlogin.php` and how an attacker would get here?
First, we need to understand that this is possible only in a Moodle instance with some kind of OAuth enabled. In it, a user can log in via their OAuth account or link/unlink OAuth to an existing account. In case it's the first OAuth login a new account will be created with linked OAuth. **But** in case there is already an account with the same email address as the OAuth account, Moodle will link those accounts and send this `confirm-linkedlogin` confirmation link by email.

<img src="/img/blogs/Moodle/image-4.webp" style="width: 100%;"/>

# Exploitation
Here are the specific number of steps an attacker would need to do to craft an account takeover attack:

1. The attacker has an account with a controlled email same as the OAuth provider (for example, if Moodle has Google’s OAuth then the email should be a Gmail address). In this demonstration, let's say an attacker is logged in with attacker@gmail.com. 

2. The attacker’s account shouldn’t be linked to OAuth (can be unlinked in the user options in case it's already linked).

3. Attacker creates a self-XSS payload that logs in using the current browser’s OAuth (done automatically without requiring credentials) using an iframe pointing to:
`/auth/oauth2/login.php?id=2&wantsurl=%2F&sesskey=${M.cfg.sesskey}` (the `M.cfg.sesskey` is the current session’s CSRF protection). Since the Iframe has the same origin as the main page, the XSS code can freely access the newly created session in the Iframe.

4. An attacker account adds the self-XSS payload to a WYSIWYG input and waits for the autosave.

5. Attacker logs out.

6. The attacker logs in with **OAuth** (using attacker@gmail.com). Moodle will see that there is already an account with the same email address and will generate a confirmation URL that links the Moodle account to the OAuth. That URL will be sent by email. 

7. Attacker adds the `redirect` parameter to the URL that will point to the self-XSS containing page: `http://moodle-domain/auth/oauth2/confirm-linkedlogin.php?token=...&userid=11&username=...&issuerid=...&redirect=http://moodle-domain/user/edit.php?id=11%231`

8. Any user who clicks on the newly crafted link will be logged in to the attacker’s account and redirected to the self-XSS page.

<img src="/img/blogs/Moodle/image-5.webp" style="width: 100%;"/>

9. The victim triggers the self-XSS payload in the context of the attacker's account. It creates a new frame in which the victim is authenticated back in their own account via OAuth. Both the parent document (attacker's session) and the frame (victim's session) share the same origin, so the payload has full access to everything inside the frame. 

<img src="/img/blogs/Moodle/image-6.webp" style="width: 100%;"/>

10. From here, the attacker has full control over the victim's account. For example, using the following iframe’s onload event code will show an alert with the victim’s cookie: `alert('hijacked cookie:' + document.cookie);`. Any other action can be done directly in the frame on the victim's behalf. In case the victim account has admin privileges, code execution on the server can be achieved (as demonstrated in our [previous](https://www.sonarsource.com/blog/playing-dominos-with-moodles-security-1/) blog).


# Patch
The vulnerability was [fixed](https://github.com/moodle/moodle/commit/3d3dd827fae6db06f8f2a265ef38cfd5566d0c17) in versions 4.2.2, 4.1.5, 4.0.10, 3.11.16, and 3.9.23 by removing the call to the `complete_user_login` function, causing the `confirm-linkedlogin.php` endpoint to not automatically login the user by clicking the link. 

```diff
- if (!$user->suspended) {
-         complete_user_login($user);
-         \core\session\manager::apply_concurrent_login_limit($user->id, session_id());

+    if ($user->id == $USER->id) {
//...
```

Clicking a malicious link now will not log in to the attacker’s account and thus no self-XSS is executed on the victim (though stored self-XSS is still possible in the WYSIWYG editor).


# Timeline
| Date    | Action |
| -------- | ------- |
| 2023-03-22 | We report all issues to the vendor |
| 2023-08-10 | Vendor patched the vulnerability |
| 2023-08-21 | Vendor released security advisory and CVE-2023-40320 was assigned |

# Summary
In this article, covering our second critical vulnerability found in Moodle, we demonstrated how attackers can leverage the self-XSS vulnerability to an impactful Account Takeover. Considering that, in addition to our first blog in the series covering another innocent initial bug to RCE, it is important to not overlook those innocuous issues. 

By focusing on clean code practices, developers write software that is clear, maintainable, and understandable. These qualities make it easier to spot and address vulnerabilities during development, reducing the risk of introducing security flaws that could be exploited by attackers. It is important to address all security issues in order to reduce the chance of bug chains.

We would also like to thank Moodle again for their responsiveness and great communication.