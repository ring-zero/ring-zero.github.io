---
layout: default
title:  "Powershell Empire — You Can Run, but You Can’t Hide"
date:   2025-07-27 15:43:00 -0400
categories: malware analysis
---

> SHA256: 82a73b268dca7cc0678aba4deb06a7b41bd6e17d72927217113992be1eec7546

I was searching the front page of the Abuse Bazaar and came across a batch script which I was interested in looking at as I don’t often analyze batch files.

https://bazaar.abuse.ch/sample/82a73b268dca7cc0678aba4deb06a7b41bd6e17d72927217113992be1eec7546/

Initial triage of the batch script in a text editor shows an obvious base64 encoded command.

![Alt text](/assets/images/2025/Empire/1-powershell1.png)

Deobfuscating this is accomplished using any preferred method of decoding base64.

![Alt text](/assets/images/2025/Empire/2-powershell2.png)

After deobfuscation, we can see a PowerShell script that is somewhat straightforward in what it is set to accomplish. We can make out based on seeing WebRequest, WebClient, and the WebClient.DownloadData method that a URI is accessed. At first glance there is no legible URI or IP address, so decoding the base64 string in the $ser variable provides an IP address.

![Alt text](/assets/images/2025/Empire/3-cyberchef.png)

Now we can see that “hxxp://193[.]117[.]208[.]148:7800”, along with admin[.]php, is an indicator of the establishment of a C2 server over port 7800. When running the malware, the connection is refused, and nothing is provided by the .php page. Using Fiddler, we can see the user agent used in the script.

![Alt text](/assets/images/2025/Empire/4-useragent.png)

As the connection fails, the listener is likely no longer configured to deliver malicious content. However, what if we directly connect to the IP address? We are presented with the index page containing what appears to be several malicious files.

![Alt text](/assets/images/2025/Empire/5-index.png)

We can see the presence of a batch file named “Client.bat”, so let’s compare that to our batch file downloaded from Abuse by comparing hashes.

![Alt text](/assets/images/2025/Empire/6-hashcompare.png)

All the hashes match.

So, what’s next? Well, downloading all the PE files from the index and doing a quick triage on all reveals that they all have a hardcoded filename of “ab.exe” While the hashes are different, they all have one thing in common — they are meterpreter executables which makes sense based on our discovery of C2 behavior. Out of curiosity, checking the shortcut file posed as a text file shows that the following command is executed.

![Alt text](/assets/images/2025/Empire/7-meterpreter.png)

Essentially, the PowerShell script serves as the stager that invokes a web request which is textbook PowerShell Empire behavior. The “193[.]117[.]208[.]148” IP and subsequent index are connected to and the “Payload.exe” file is downloaded and saved to the active user’s temp folder. As mentioned earlier, this is a meterpreter payload.

How do we identify MetaSploit with a quick triage? Well, there’s a few ways. Firstly, the PE file is not obfuscated as usual, and its strings are ripe for picking. Strings of interest in this case are:

> User-Agent: ApacheBench/

> Licensed to The Apache Software Foundation, http://www.apache.org/<br>

> Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>

> This is ApacheBench, Version %s <i>

> Usage: %s [options] [http://]hostname[:port]/path

> C:\local0\asf\release\build-2.2.14\support\Release\ab.pdb

> ApacheBench command line utility

…and so on.

MetaSploit leverages Apache Benchmark to create payloads. The payloads contain strings seen above and the hardcode file name is always “ab.exe”. This analysis is an example that PowerShell Empire continues to be a ruinous post-exploitation tool. Moreover, threat actors are getting crafty in what lengths they are going to set up their stager for attempts to circumvent detection.

Additional information here: https://seclists.org/metasploit/2013/q3/13

Thanks for reading!