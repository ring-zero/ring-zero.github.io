---
layout: default
title:  "Formbook Shellcode Analysis"
date:   2025-07-04 18:28:00 -0400
categories: malware analysis
---
> MD5: 4ff264c2efd8c0bba69030aa6a5fe31e

> SHA1: 67d1da5490277818ee07faaa22c6e0314a80c2ef

The document arrived via a phishing email with the usual format.

![Alt text](/assets/images/2025/Formbook/1-phishing-email.png)

Performing an exact search for "s.lebli@gass-dz[.]com" takes us to "hxxp://www[.]gass-dz[.]com/#"

![Alt text](/assets/images/2025/Formbook/2-phishing-site.png)

According to AbuseIPDB, the website has been flagged several times for fraud orders, web spam, and email spam.

Before beginning analysis, the file was renamed to bad.doc for clarity. Running TrID on the file produced a high confidence for the .PZ2 file extension, as well as mention of the RTF format. I am currently unsure as to why TrID strongly associates the file with an extension pertaining to Poser, a 3D figure design program.

![Alt text](/assets/images/2025/Formbook/3-trid.png)

The traditional file command can be run against the file as well to be prompted with the usual "Rich Text Format data, version 1, unknown character set."

As the file was labeled to be an RTF, initial triage was conducted using rtfdump.py.

![Alt text](/assets/images/2025/Formbook/4-rtfdump1.png)

Examining the index number of each group, #3 appears to contain an embedded object with an MD5 hash and a magic number.

For a more streamlined approach to discovering embedded objects in an RTF, you can append the "-O" parameter to trim the group structure. Alternatively, you can use the "-O" parameter anyway to confirm your original object assessment. In the case of our RTF, there was a single object assigned to index #1.

![Alt text](/assets/images/2025/Formbook/5-rtfdump2.png)

To dump an embedded object in an RTF file with rtfdump.py, you can use the following parameters: "-O" for objects, "-s" for the index #, and "-d" for dump. After dumping the object from index #1 in our RTF to a new file I called "bad.object", TrID listed the file as "Unknown!" However, running the file command states the the file is data.

With what we have seen so far in this analysis, we can guess that the dumped object being of the data type according to the file command may be a .bin (or shellcode). To confirm this, we can use the xorsearch tool with the "-W" parameter to parse the file for shellcode. The "-d 3" parameter ignores ROT transformation to reduce false positives.

![Alt text](/assets/images/2025/Formbook/6-xorsearch.png)

xorsearch discovered the existence of GetIP in clear text (XOR 00) at the position of 97A. Knowing that this file now contains strong indicators of shellcode, scdbg will aid in emulating its execution. As we are interested in terminal output of scdbg, we append the "c" character to the command, whereas the GUI version would remain scdbg.

The following command will emulate the shellcode located at 97A with no instruction restrictions as we don't know how many may be involved yet: "scdbgc /f bad.bin /s -1 /foff 97A"

![Alt text](/assets/images/2025/Formbook/7-scdbg.png)

From the output, it doesn't seem that the shellcode involves any file handle checking, although I may need to pivot elsewhere in my analysis to have a definitive answer.

> **401d07**: The shellcode first calls GetProcAddress with the lpProcName parameter set to retrieve the ExpandEnvironmentStringsW function.

> **401d54**: The %APPDATA% environment variable is associated with the string "%APPDATA%\founderod74hj43.exe"

> **401d69**: LoadLibraryW is called with the parameter lpLibFileName to load the UrlMon library for subsequent download functionality.

> **401d84**: GetProcAddress is called with the lpProcName parameter set to retrieve the URLDownloadToFileW function. URLDownloadToFileW is commonly associated with downloader activity in malware.

> **401dde**: URLDownloadToFileW is called with the szURL parameter set to the URL containing the download of the "founderz.exe" from the listed IP, followed by the szFileName parameter set to the path and name of the file where the .exe will be saved. I assume that the username in the shellcode excerpt is set to "remnux" as I ran the shellcode on a REMnux box with the username set to "remnux".

> **401df6**: GetProcAddress is called with the lpProcName parameter set to retrieve the GetStartupInfoW function.

> **401e00**: I am not confident in what is occurring here with GetStartupInfoW, but I believe it may indicate a pointer to the buffer related to 12fda4.

> **401e17**: GetProcAddress is called with the lpProcName parameter set to retrieve the CreateProcessW function, setting the stage for spawning a malicious process.

> **401e3c**: CreateProcessW spawns the "founderod74hj43.exe" process that was downloaded earlier and placed into the user's Application Data folder. The "0x1269" value may indicate the process ID associated with the process, although I am not confident.

> The final calls pertain to exiting the process.

The hardcoded IP "208.67.105.179" has hosted malware such as AgentTesla, Loki, AZORult, SnakeKeylogger, DarkCloud, GuLoader, RedLineStealer, and more.

![Alt text](/assets/images/2025/Formbook/8-strings.png)

Like many documents with embedded malicious macros or objects, the beginning of the document reveals the social engineering attempt to have the user enable content to execute the macro. This sample's avenue of approach is by stating that the document was created in an older version of Word. The following string padding is implemented to attempt for obfuscation and anti-detection efforts.

Thanks for reading!