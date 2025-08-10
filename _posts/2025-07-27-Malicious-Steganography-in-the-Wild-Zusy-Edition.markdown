---
layout: default
title:  "Malicious Steganography in the Wild: Zusy Edition"
date:   2025-07-27 15:35:00 -0400
categories: malware analysis
---

![Alt text](/assets/images/2025/Zusy/1-flowchart.png)

The malware first arrives as an .img file which is typically used to bypass mark-of-the-web (https://attack.mitre.org/techniques/T1553/005/) and execute the malicious archive files by mounting the image. As the .img is an archive, using 7-zip or the like will allow us to see what the contents are.

![Alt text](/assets/images/2025/Zusy/2-vbs1.png)

Inside the .img is a .vbs file named “statement.vbs” Thus, when the .img file is mounted and the user interacts with it, the .vbs file will execute. Of course, as a .vbs file is a script, it can be viewed in your favorite text editor.

![Alt text](/assets/images/2025/Zusy/3-vbs2.png)

Reviewing the initial code of the script appears to be a slmgr script which is typically used for Windows product activation tasks. In recent script-based malware that I have seen in the enterprise, authors might nest their malicious code inside of legitimate libraries or code for additional obfuscation purposes. Typically, the code that appears legitimate does not actually run which I believe is the case with this script. Security researchers or malware devs can correct me if I am wrong.

For this specific script, line 626 shows a call to the function Connect().

![Alt text](/assets/images/2025/Zusy/4-vbs3.png)

It appears to be a declaration of obfuscated variables. From here, we can trace Connect() to find the subroutine code to see what’s going on.

![Alt text](/assets/images/2025/Zusy/5-vbs4.png)

The first part of the code is an if statement that can be broken down. The variables objLocator, strOutput, objServer, objService, strErr, and strVersion are declared. “On Error Resume Next” is used to ignore runtime errors, ensuring execution continues.

The script then checks if the variable “g_strComputer” is set to “.”, which indicates the local computer. If it is the local computer, the script connects to the local WMI namespace and Registry and then exits. If the script is not executing on a local machine, a connection attempt to a remote machine is attempted. In this case, as the machine is local, return.

![Alt text](/assets/images/2025/Zusy/6-vbs5.png)

Scrolling through the obfuscated code, we see a “Set” which assigns the variable “WBYlEXQlmPxchfravhNPEzAlsiZkJWIrJQLLQNQtjYLtcTNBBb” to “Set “WScript.CreateObject(“WScript.Shell”)”

![Alt text](/assets/images/2025/Zusy/7-vbs6.png)

There’s a bit to unpack here as far as obfuscated variables and involvement of the Replace function. Specifically, we see the variable “FkpuberwJZJMDxXJpvYmBlZQSUGtGmazoZwhwfsMdonqExBdup” with several call operators for “$OWjuxd” that are broken up. If we put it all together, we get “[system.Convert]::Frombase64string($codigo.replace(‘DgTre’,’A’)));powershell.exe”

There is also another replace for “KcvJZikKXNPGBykcYJaOtRKLDQyTDIWvIYWrkpiwOtqhwWrWli, saKJyNDyaRINMWrdZvxvMvuKghbviUPTniOGBmNQKfWjqXGlDN + lpUdYWlcNlKOjhSJqjLucXAUsGqwXPeGCjKWDDWpKPgOqjWWdW” with “Z”

Looking a bit lower in the code, we see “-windowstyle hidden -executionpolicy bypass -NoProfile -command $OWjuxD”” Basically, “$OWjuxd” execution creates a WScript shell that performs a string replacement.

Now that we know the string “DgTre” will be replaced with “A”, we know where to proceed. We can either scroll up to the beginning of the Connect() function or perform a search for “DgTre” and then go to the first one. Spolier alert, it’s a very large obfuscated base64 string.

![Alt text](/assets/images/2025/Zusy/8-vbs7.png)

After replacing all instances of “DgTre” with “A”, we get a much smaller string. However, we are not there yet. Let’s remove all white space and ampersands and take a look at what we have.

![Alt text](/assets/images/2025/Zusy/9-vbs8.png)

Shortened for purposes of the post of course, but it’s looking like a much more digestible base64 string. Let’s now replace what was mentioned earlier with “Z”

![Alt text](/assets/images/2025/Zusy/10-vbs9.png)

Awesome, we are now good to convert from base64. As usual, CyberChef’s frombase64 and decode to UTF 16LE recipes will do the job.

![Alt text](/assets/images/2025/Zusy/11-cyberchef.png)

And here’s our WScript PowerShell in its deobfuscated form. The “uploaddeimagens” domain is connected to and a .jpg file is downloaded.

![Alt text](/assets/images/2025/Zusy/12-screenshot.png)

What’s interesting is seeing “<<BASE64_START>>” and “<<BASE64_END>>” We can also see the download and creation of a file from a reversed URL. Let’s use Notepad++ to make it readable: “hxxps://paste[.]ee/d/Tykxm/0” This file is placed into the “C:\ProgramData” directory with the filename “VbsName” and will be executed on reboot for persistence.

![Alt text](/assets/images/2025/Zusy/13-vbs10.png)

The script fetches the content of the paste[.]ee URL using an HTTP GET request and then executes the received content to ensure persistence as noted above. Additionally, a run key is also added to run the .vbs file on startup.

The malicious image file from the “uploaddeimagens” domain was still available, so naturally I downloaded it to take a look. If we view the file in a hex editor and scroll towards the trailer, we see our “<<BASE64_START>>” that we saw earlier. Scrolling to the end of the trailer shows the “<<BASE64_END>>”

![Alt text](/assets/images/2025/Zusy/14-hxd1.png)

Putting this base64 string into CyberChef shows “MZ” shows the existence of a PE file.

![Alt text](/assets/images/2025/Zusy/15-cyberchef2.png)

The cool thing about CyberChef is that you can save the decoded contents to disk, which is great to be able to further analyze what we expect is more malware. There are a lot of interesting strings in the PE file, such as a leftover debug symbol path of “H:\New Private Panell Src 3.0\New Metod Defender Dll\ClassLibrary3\ClassLibrary3\obj\Debug\ClassLibrary3.pdb” Thus, we can expect the file to be a .DLL named “ClassLibrary3.dll”.

As this PE file is a .NET-based .DLL, it can be brought into dnSpy for a deeper analysis.

![Alt text](/assets/images/2025/Zusy/16-dnspy.png)

Of interest in the code is a string reversed URL which downloads another image file that is to be injected into the Windows process “RegAsm.exe”

![Alt text](/assets/images/2025/Zusy/17-screenshot2.png)

When downloading the file from the URL and opening it in a hex editor to view the base64 like earlier, the bytes are reversed this time.

![Alt text](/assets/images/2025/Zusy/18-hxd2.png)

Using the same Python script that I used in my WhisperGate analysis to reverse the bytes, we can then get the correct base64 to paste into CyberChef in order to dump the file to disk.

The dumped executable is another PE file with the debug path of “c:\users\cooder\desktop\new metod defender dll\classlibrary1\obj\debug\rump.pdb” and an original filename of “Rump.dll” As it is another .NET-based PE file, dnSpy reveals that the DLL file is the payload that is injected into “RegAsm.exe” by creating the suspended process and using WriteProcessMemory to write the malicious code and then resume the process with ResumeThread.

Taking the hash of this payload PE file (52575032c7eb4b3816b0e8a57ee4ea1cf19aacb32c3e2f96b8a891fe4ba2bcac) to VirusTotal shows high confidence in this being related to the Zusy malware. Zusy, aka TinyBanker or Tinba for short, is a known banking trojan. This sample is likely a new variant that was released to the wild within the last several months as this is the first variant I have personally seen using steganography.

Thank you for reading!