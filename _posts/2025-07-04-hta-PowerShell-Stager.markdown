---
layout: default
title:  ".hta PowerShell Stager"
date:   2025-07-04 19:35:00 -0400
categories: malware analysis
---
> SHA256: 2fe621fe3a33dbf93d5fb71605ad76048ef621d14585eb4ff9f495ce8a6992fa

I don’t look at PowerShell malware often, so I wanted to kill two birds with one stone by doing that and also diving into my first .hta sample.

Many moons ago (1999, to be exact), Microsoft introduced the .hta file extension which contains dynamic HTML code and script code supported by IE such as VBScript or JScript. The HTML code would render the user interface of the application, and the scripting code would provide the logic. While .hta is no longer officially supported in modern versions of IE or Edge, the Windows internals functionality of it are very much abused, with a continuing rise as a stager in recent malware.

By default in Windows, .hta files are associated with mshta.exe which is the native application which executes Windows script host code in an .hta file. Naturally, threat actors use this as a LolBin method to trick users into executing malicious scripts. The “benefit” of .hta applications for serving as a malware stage 1 is that mshta.exe executes the script code outside of the browser, bypassing any security controls.

While .hta files are executable, their contents are still script-based, therefore, we can view the code in a text editor.

![Alt text](/assets/images/2025/hta/1-hta.png)

Right off the bat we can see that there are some interesting choices for variable names, but the meat of the script is legible. From a rough glance, a WScript Shell is created with ActiveX using cmd.exe which spawns a hidden PowerShell window, executes whatever code is obfuscated in the base64 encoded string, and closes the window.

If we copy the string into CyberChef, we are presented with the following results:

![Alt text](/assets/images/2025/hta/2-cyberchef.png)

We can clean this up by decoding the text as it is encoded with UTF-16LE.

![Alt text](/assets/images/2025/hta/3-clean1.png)

Going further, we will beautify this even more by saving the contents to a .ps1 file to enable proper syntax highlighting.

![Alt text](/assets/images/2025/hta/4-ps1clean.png)

Let’s break this down one by one. First, kernel32.dll and msvcrt.dll are used with DLLImport to import three APIs that are historically known to be involved with injection: VirtualAlloc, CreateThread, and memset. Next, the hex byte values are shellcode and correspond to the variable $s0 which copies the shellcode to memory and injects it to the PowerShell instance with VirtualAlloc and memset.

Before analyzing the shellcode, we can clean it up by replacing all instances of “,0x” with nothing.

![Alt text](/assets/images/2025/hta/5-clean2.png)

Taking the cleaned hex output and running it through the “FromHex” recipe provides us with the following.

![Alt text](/assets/images/2025/hta/6-fromhex.png)

While messy, we can make out a few bits of useful information.

1. An IP address (redacted)

2. Mention of WinInet, the API used when malware utilizes imports associated with downloading files, etc.

In summary, it appears that this script exists to create a reverse shell which the author(s) likely use to deploy additional malware and other nefarious actions against the user. This behavior has been seen in the Rozena malware over the last several years.

Thanks for reading!