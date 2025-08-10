---
layout: default
title:  "PirateFI: A look into fake Steam games, infostealing, and Steam and Telegram C2."
date:   2025-07-27 16:00:00 -0400
categories: malware analysis
---

![Alt text](/assets/images/2025/PirateFI/1-piratelogo.png)

Picture acquired from: https://www.howtogeek.com/steam-malware-game-piratefi/

I was doomscrolling on YouTube and the algorithm decided to show me a video: [PirateFi — Fake Game — Trojan virus on steam](https://www.youtube.com/watch?v=MJGMzYSoWLc). I hold no affiliation to the content creator behind this video, but I always try to give credit where credit is due as I would not have known about this otherwise.

PirateFi is (was) a decoy game published on Steam to infect its victims with an infostealer. There are several articles covering the issue, such as BleepingComputer’s, but I could not find an analysis post or report. That said, I set out to find the game’s installer to do a quick analysis.

This was not as straightforward as I thought it would be because the game was rightfully vaporized by Valve after many reports of victim infections and compromised accounts/wallets. Of course, none of the articles provided any kind of hash which is completely expected.

So, I did what I have been doing lately which is to query VirusTotal as I am lucky enough to have a license. The search term I used was “Lazzzy.gen” which led me to a ZIP archive containing PirateFi.

Initial triage reveals that PirateFi, naturally, begins as a setup executable compiled with Inno Setup version 5.5.7, approximately ~677 megabytes in size.

![Alt text](/assets/images/2025/PirateFI/2-triage.png)

I found it interesting that the certificate is issued by Sectigo Public Code Signing CA R36 to an individual, not an organization or otherwise. Moreover, it’s not just an individual’s full name, but their email address. Allegedly, OSR shows the individual is a Kenyan software developer. I obfuscated their information as I will not dox this individual in a public blog post, especially if this is a stolen certificate.

![Alt text](/assets/images/2025/PirateFI/3-pestudio.png)

Inno Setup-based executables can be extracted, which is helpful as the install_script.iss files typically reveal the intent behind the behavior post-install. For this file specifically, the script inevitably creates an executable named Howard.exe in the \temp directory and then automatically executes it.

![Alt text](/assets/images/2025/PirateFI/4-scriptiss.png)

Executing the Inno Setup “Pirate.exe” installer follows the common Inno Setup flow, just with IOCs specific to this infection.

> 1) The setup runs with the /VERYSILENT parameter which ensures no windows are displayed to assist in evading victim suspicion.

> 2) Creates the Pirate.tmp file in the \temp directory.

> 3) Enumerates the task list for the Quick Heal AV and Sophos endpoint security.

> 4) Creates Howard.exe in the \temp directory.

![Alt text](/assets/images/2025/PirateFI/5-howardtemp.png)

Howard.exe’s job is the payload, as in it is the primary functionality behind the infostealer. Of an exhausting list, some of the platforms it looks for and if found will attempt to steal from are:

> 1) Browser data.

> 2) Productivity apps such as LotusNotes.

> 3) U.S. and international email services (example: Poczta o2).

> 4) U.S. and international social media platforms.

The list goes on.

The means in which this malware communicates with the C2 infrastructure for exfiltration and acquisition of additional malware is neat, as the attacker’s leverage Telegram (149[.]154[.]167[.]99) and Steam. The Steam C2 that is contacted is based on a SteamID which hosts 95[.]216[.]180[.]186 and is communicating files significant to the infection.

![Alt text](/assets/images/2025/PirateFI/6-telegram.png)

![Alt text](/assets/images/2025/PirateFI/7-virustotal.png)

This behavior and many of the IOCs present mirror Vidar Stealer incredibly closely.

Overall, that’s it for this analysis. I did not want to get into the weeds but instead give a quick look into how Steam can not only host malware, but also serve as a platform for C2 communication. Thanks for reading!