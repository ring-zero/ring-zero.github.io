---
layout: default
title:  "Dismantling Hermetic Wiper’s Little Brother: WhisperGate"
date:   2025-07-27 15:22:00 -0400
categories: malware analysis
---

> Stage 1 MBR: a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92

> Stage 2 Downloader: dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78

> Stage 3 Wiper Dumper: 923eb77b3c9e11d6c56052318c119c1a22d11ab71675e6b95d05eeb73d1accd6

The motivation to analyze this threat came from recent internal alerts in my organization pertaining to behaviors associated with Cadet Blizzard, the Russian GRU-sponsored threat group.

Per Cybersecurity and Infrastructure Security Agency (CISA) advisory, WhisperGate is a destructive malware deployed by Cadet Blizzard against the Ukraine since 2022. Like HermeticWiper, WhisperGate’s intent is to render its infected systems inoperable. In the context of malware, this is typically accomplished by destroying or overwriting the default contents of the Master Boot Record (MBR).

Performing initial static analysis on the stage one sample identified by CISA reveals details that aid in steering analysis efforts. Firstly, only 21 imports are utilized from kernel32.dll.

![Alt text](/assets/images/2025/WhisperGate/1-kernelimports.png)

The executable was compiled with MinGW and is interestingly not packed.

![Alt text](/assets/images/2025/WhisperGate/2-trid.png)

Examining the executable’s strings shows a notification that the hard drive is corrupt, and restoration requires a Bitcoin payment to the threat actor’s wallet.

![Alt text](/assets/images/2025/WhisperGate/3-mbrcorrupt.png)

Moving on, the goal is to find the code we are interested in, which occurs by jumping to the operand from the subroutine of 403B60.

![Alt text](/assets/images/2025/WhisperGate/4-subroutine.png)

One string of significant interest we immediately see is \\.\PhysicalDrive0. The “\\.\” prefix will access the Win32 device namespace instead of the Win32 file namespace. Consequently, access to physical disks and volumes is accomplished directly without incorporating the file system which is beneficial for threat actors. Specifically, this malware uses CreateFileW with “\\.\PhysicalDrive0” as these device names are created by the system as these devices are enumerated.

![Alt text](/assets/images/2025/WhisperGate/5-createfilew.png)

Based on the parameters, the \\.\PhysicalDrive0 device is opened if it exists, and a handle is created in EAX and moved to ESI.

![Alt text](/assets/images/2025/WhisperGate/6-eaxesi.png)

What I find surprising is that despite WhisperGate being crafted with its political, destructive intent in mind, it features a lack of anti-debugging and usual sophistication.

> Existence of TLS callbacks (2) but no actual usage of them for thwarting analysis efforts.

> Not packed which results in plaintext strings.

> Lack of sanity checks when creating the handle (EAX) and moving into ESI.

In any case, after obtaining the handle, 512 bytes are written to the MBR with WriteFile. What is written to the MBR, though? We can check what is in ESI and are presented after scrolling a bit with the MBR string we saw above.

![Alt text](/assets/images/2025/WhisperGate/7-smallstrings.png)

As it’s not very friendly to the eyes, expanding the strings to a word-wrap format is accomplished with the ‘A’ key.

![Alt text](/assets/images/2025/WhisperGate/8-fullstrings.png)

Of note from the above image is the presence of 0xAA55 which is the MBR signature or starting sector of \\.\PhysicalDrive0 which can be expanded upon by displaying the hex contents.

![Alt text](/assets/images/2025/WhisperGate/9-hxd1.png)

The hex contents can be dumped to then load as an additional binary file to drill down on the actual code modifying the MBR. There is a loop structure involved with the interaction of the string. There is a pointer si to the string notifying the victim that their hard drive has been corrupted, followed by obtaining the first byte from si, comparing it to zero, and then if zero, call the function that prints the character of the string in al to the screen. Essentially, the loop’s intent is to continually print the characters in the string to the screen until the entire string has been written.

Before proceeding to stage two analysis, dynamically analyzing the flow of stage one provides a visual perspective as to how simple, yet destructive it is to tamper with the MBR. Firstly, it would be interesting to see the MBR overwritten in real-time, so x32dbg is helpful in doing this in a controlled manner.

Remembering above where I mentioned that there are two TLS callbacks, we need to get through those first to reach the EP. While there are many ways to do this, especially as they do not exist for anti-debugging purposes, I opted to set a BP on .EntryPoint and then run until I reached it.

Upon reaching the EP, the goal is to navigate to CreateFileW, set a BP, step over, and view the controlled pause of the rewritten MBR. Before checking a hex editor and viewing the hard disk, refreshing and observing active handles reveals the successful handle creation to disk 0.

Running HxD as administrator enables access to the disk 0 to display the modified MBR post-closure of the handle.

![Alt text](/assets/images/2025/WhisperGate/10-hxd2.png)

Self-executing the malware and reviewing a capture log file in ProcDot shows how straight-forward its destruction process is.

![Alt text](/assets/images/2025/WhisperGate/11-procdot.png)

After opening the handle with CreateFileW, the 512 bytes of modified code is written to disk 0 using WriteFile. The size of the written bytes being 512 is confirmed by navigating to the WriteFile event in ProcMon.

![Alt text](/assets/images/2025/WhisperGate/12-procmon.png)

As the malware does not force a restart and instead waits for a manual, user-initiated restart or shut-down, notification of the corrupted MBR is not visible right away. After restarting my lab, I was presented with the following.

![Alt text](/assets/images/2025/WhisperGate/13-mbrcorrupt2.png)

If it isn’t obvious by now, even if the user pays the ransom, the threat actor cannot (and will not) rebuild the MBR for the user. This is a double win for the threat actor as they may trick organizations into paying ransom, but they also destroy the affected system(s) in the process as intended.

The concept of stage two with WhisperGate is not something I have seen before. That is to say that all stage one malware samples I have seen exist to “set the stage” for the payload. For example, a Word document that arrived via a phishing email containing a malicious macro that uses URLDownloadToFile to pull the payload and then executes it. With stage one of WhisperGate, corruption of MBR is all there is, yet CISA identifies a separate executable as the second stage.

According to DIE, the stage two file is .NET-based executable containing a compromised certificate from Microsoft Corporation.

![Alt text](/assets/images/2025/WhisperGate/14-die.png)

![Alt text](/assets/images/2025/WhisperGate/15-cert.png)

When examining the code in dnSpy, there is a method “Facade.UpdateItem” that is called with several parameters. In short, the code reflectively retrieves the “DownloadData” method from the “WebClient” class, which is apparent with slight character replacement for obfuscation, and using the “WebClient.DownloadData” method, downloads the “.jpg” file from the Discord link that is stored in the objects array.

![Alt text](/assets/images/2025/WhisperGate/16-dnspy.png)

However, this code does not execute immediately upon access of the file. Instead, there is a loop which contains code to open a hidden PowerShell window and execute a base64 encoded command. As there are two split base64 strings, clearly indicating concatenation during runtime, a trip to CyberChef tells us the following.

![Alt text](/assets/images/2025/WhisperGate/17-cyberchef.png)

Decoding the base64 reveals that a 10 second sleep is initiated upon execution of the sample, and “num2” is incremented. The loop ensures that if num2 is < 2, run again until it is, ensuring a 20 second sleep. Like all malware leveraging sleep maliciously, sleep is used to thwart analysis efforts by tricking the analyst into thinking nothing happened upon execution.

Dynamic analysis of the stage two executable reveals much of what we saw in dnSpy, but in real-time. For example, Process Hacker displays the expected process tree containing the hidden PowerShell that executes the encoded command.

![Alt text](/assets/images/2025/WhisperGate/18-prochack.png)

Drilling down on the PowerShell process and reviewing its command line field displays the expected encoded command.

![Alt text](/assets/images/2025/WhisperGate/19-powershell.png)

As the Discord payload link is now 404, OSR on the URL reveals that it resolved from a Cloudflare IP (162[.]159[.]130[.]233) that has been associated with hundreds of malicious files. The malicious URL used in this malware holds relations to several interesting artifacts.

![Alt text](/assets/images/2025/WhisperGate/20-virustotal.png)

While the stage three sample is available on VirusTotal, it is the raw file from the Discord link above that would be downloaded as if the link was accessed as intended by the malware. That is to say that the file has reversed bytes and will not serve any purpose until the bytes are reversed again to make it a proper PE. Opening the file in HxD shows the MZ header in the trailer.

![Alt text](/assets/images/2025/WhisperGate/21-hxd3.png)

As I cannot have the stage two malware reverse the file that is pulled from the Discord link as intended, I opted to make a simple Python script with the sole purpose of reversing bytes in the stage three sample for this analysis.

![Alt text](/assets/images/2025/WhisperGate/22-python.png)

After running my ugly script against the file and creating the cleaned version, it can now be analyzed as it is a valid PE. A quick check in DIE notes that it is a .NET-based executable like the stage two sample but is obfuscated with Eazfuscator. Eazfuscator is a popular, commercial .NET obfuscator with a friendly GUI that provides a straightforward protection process.

There are several ways to deobfuscate Eazfuscator, with de4dot being the first attempt. However, the problem I encountered with de4dot is that it was purging strings necessary for functionality. The workaround to this is cloning EazFixer and running it against the executable.

One of the resources in the sample, 78c855a088924e92a7f60d661c3d1845, is loaded into memory and, with XOR decryption, creates the DLL file zx_fee6cce9db1d42510801fc1ed0e09452.dll. This DLL file ensures that two resources (executables) named AdvancedRun and Waqybg, are run.

Waqybg is the final stage that exhibits ransomware behavior as it corrupts files on the disk and renames them with a random 4 digit number. This is accomplished by using SetRenameInformationFile’s ReplaceIfExists which returns false.

![Alt text](/assets/images/2025/WhisperGate/23-aftxt.png)

Alternatively, if anyone reading this is curious as to how to build a custom loader to have 78c855a088924e92a7f60d661c3d1845 loaded into memory to continue execution, I came across an AWESOME post from Max Kersten during my research at this point in the analysis as to how to accomplish this. Max is an insanely talented malware analyst and I highly recommend reading the entire post.

In summary, WhisperGate was a fantastic learning experience as it was my first time analyzing MBR malware and encountering reversed bytes in a sample.

Thanks for reading!