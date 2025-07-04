---
title: "CVE-2021-33420: NPM Replicator Remote Code Execution Deserialization"
date: 2021-06-14
tags:
	- "npm"
	- "deserialization"
	- "rce"
advisory: false
origin: https://checkmarx.com/blog/npm-replicator-remote-code-execution-deserialization
cves:
	- "CVE-2021-33420"
star: true
---
# Introduction
NPM, the package manager for Node.js, is an open source project that serves as a critical part of the JavaScript community and helps support one of the largest developer ecosystems. According to its [website](https://www.npmjs.com/), "npm is relied upon by more than 11 million developers worldwide. The free npm registry has become the center of JavaScript code sharing, and with more than one million packages, is the largest software registry in the world."

Given the breadth of the npm universe and the Checkmarx Security Research Team’s always-on curiosity into performing investigations into open source projects and uncovering 0-days, we recently conducted an npm-focused vulnerability workshop. As a result of our efforts, we discovered an interesting remote code execution (RCE) deserialization issue in the npm [Replicator](https://www.npmjs.com/package/replicator) package.
# Impact Summary
Deserialization of any untrusted input in the npm Replicator package, which sees more than 200,000 downloads per week, could lead to remote code execution and full compromise of the machine.

# Overview
Replicator is an "advanced JavaScript objects serialization" package in npm. This package wraps around the JSON parse and stringify functions, and provides additional functionalities to it. On top of the JSON key-value pairs, Replicator adds support for the following 9 objects:

* undefined
* NaN
* Date
* RegExp
* Error
* Map
* Set
* ArrayBuffer
* Typed arrays

# Details
First, let's get a general idea of how Replicator serializes and deserializes those unsupported JSON objects. When trying to serialize a ***Set*** object for example, the following output will be generated:

<img src="/img/blogs/replicator/Image-1.png" style="width: 100%;"/>

The object ***Set*** was changed to a valid JSON with the key "@t" pointing to the type of the object inside the double brackets "[[***type***]]", and the parameters passed to the object are under the "data" property.

When researching these types of packages, it’s interesting to focus on the deserialization component since it is more likely that a user input would be string passed to the deserialization code rather than an object passing to the serialization code.

After checking how the deserialization is implemented in the code, the first 8 types seemed safe. However, with further examination, we came across an issue at the last object type – ***TypeArray***.

<img src="/img/blogs/replicator/Image-2.png" style="width: 100%;"/>

The function on the bottom is the one responsible for the deserialization. With that, let’s serialize one of the TypeArrays – ***Int8Array***:

<img src="/img/blogs/replicator/Image-3.png" style="width: 100%;"/>

The property "ctorName" states the object name of the ***TypeArray*** and the "arr" is the object value. But the issue in the code is that there is no validation that the object name in "ctorName" is actually a ***TypeArray*** object. When serializing, on the other hand, there is a validation using the list "TYPED_ARRAY_CTORS" defined earlier.

<img src="/img/blogs/replicator/Image-4.png" style="height: 30%;width: 30%;"/>

Looking at the code shown before we can invoke "new" on every function under the GLOBAL object with our own parameters. Something like this:

<img src="/img/blogs/replicator/Image-5.png" style="width: 50%;"/>

From here, there are limitations that we need to bypass in order to achieve the code execution.

1. From the "fromSerializable" function check, the "ctorName" must be a name of a function.
2. The function must be a constructor.
    * Hence, we can’t just call "Eval" because it’s not a constructor.

<img src="/img/blogs/replicator/Image-6.png" style="width: 70%;"/>

3. Must be a direct descendent of the GLOBAL object.
    * It’s impossible to call a function like "child_process.exec(‘evilcode’)" because we control only the value inside the brackets

<img src="/img/blogs/replicator/image-7.jpg" style="width: 100%;"/>

4. Must be a valid JSON.
    * As mentioned before, Replicator wraps around JSON parse and stringify. Due to that, the input string given to the decode function gets "JSON.parse" before going into the problematic "fromSerializable" function. So, calling "setImmediate" / "setInterval" / "setTimeout" isn’t possible because it requires a callback function as an input and that isn’t JSON valid.

<img src="/img/blogs/replicator/Image-9.png" style="width: 100%;"/>

The following payload will fail at JSON.parse before invoking a new setTimeout:

<img src="/img/blogs/replicator/Image-10.png" style="width: 100%;"/>

There is a way to pass a string (which is a JSON valid input) that will be converted to JavaScript code. Using a new "Function" will create an anonymous function with our payload, but it will not get executed.

<img src="/img/blogs/replicator/Image-11.png" style="width: 70%;"/>

At this point, it looks like we cannot go further, but there are still some security concerns and vulnerabilities despite the limitations:

* Calling an arbitrary function created by the application using replicator, which heavily depends on the application and the specific situation, something like:

<img src="/img/blogs/replicator/Image-12.png" style="width: 50%;"/>

* Local file inclusion using "require" could lead to other vulnerabilities, such as: XSS, RCE, sensitive information disclosure, and more. This, as well, depends on the attack scenario.

<img src="/img/blogs/replicator/Image-13.png" style="width: 50%;"/>

* Etc...

After fuzzing and some more research, we asked ourselves what happens if we serialize a ***Set*** within a ***Set***. What would that look like? Is it done recursively?

<img src="/img/blogs/replicator/Image-14.png" style="width: 100%;"/>

When understanding that the serialization/deserialization is done recursively, the payload to an RCE was around the corner. As mentioned before, we can create a new "Function", but nothing will run it, and we can call "setTimeout," but have to give it a function to execute.

Combining these two, here is the final payload to trigger code execution:

```js
replicator.decode('[{"@t":"[[TypedArray]]","data":{"ctorName":"setTimeout","arr":​{"@t":"[[TypedArray]]","data":{"ctorName":"Function","arr":" process.mainModule.require(\'child_process\').exec(\'calc\');"}}​}}]')
```

<img src="/img/blogs/replicator/Image-15.png" style="width: 100%;"/>

The inner object will create a function with the code input as a string, and the other object, "setTimeout", receives the function as an argument and runs the code.

Depends on the scope of the program, the shell exploit code could change. For example, in the picture above, the payload was: `require(\'child_process\').exec(\'calc\')` without `process.mainModule` because it was run in a REPL console.

# Recommendations
To avoid issues like this, update the npm Replicator package to version 1.0.4 or later.

# Summary of Disclosure and Events
After discovering and validating the vulnerabilities, we notified npm of our findings and worked with them throughout the remediation process until they informed us the issues were appropriately patched. NPM's responsiveness and professionalism throughout the process are commendable.

# Timeline of Disclosure
| Date    | Action |
| -------- | ------- |
| March 24, 2021 | Vulnerability was reported responsibly |
| March 24, 2021 | Checkmarx SCA customers using npm and Replicator were warned and provided mitigation guidance, * without exposing the technical details of the findings |
| May 14, 2021 | Pull request to fix the issue was created |
| May 17, 2021 | Fixed version 1.0.4 was released on NPM |
| May 17, 2021 | Advisory with the full details was published on the Checkmarx advisory website |
| December 15, 2022 | CVE-2021-33420 published |

# Final Words
Discovering vulnerabilities like the ones documented in this report is why the Checkmarx Security Research Team performs investigations into open source projects. With open source making up the vast majority of today’s commercial software, security vulnerabilities must be taken seriously and handled carefully across the industry.

Solutions like [Checkmarx SCA](https://checkmarx.com/product/cxsca-open-source-scanning/?) are essential in helping organizations identify, prioritize, and remediate open source vulnerabilities more efficiently to improve their overall software security risk posture. Checkmarx SCA customers receive notice of issues like the ones described above in advance of public disclosure. For more information or to speak to an expert about how to detect, prioritize, and remediate open source risks in your code, contact us.

# References
* [Issue](https://github.com/inikulin/replicator/issues/16)
* [Pull request](https://github.com/inikulin/replicator/pull/17)
* [Fixing Commit](https://github.com/inikulin/replicator/commit/2c626242fb4a118855262c64b5731b2ce98e521b)
* [Advisory](https://advisory.checkmarx.net/advisory/CX-2021-4787)