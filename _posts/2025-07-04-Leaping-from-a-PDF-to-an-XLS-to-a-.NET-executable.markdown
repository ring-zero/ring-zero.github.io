---
layout: default
title:  "Leaping from a PDF to an XLS to a .NET executable"
date:   2025-07-04 19:20:00 -0400
categories: malware analysis
---

> SHA256: 121cecaac2ed051a4b47f991e344232edf93b22d543a83d07e32f4840a579551

This malware first arrives as a PDF which is spread as malspam with a phishing campaign. Running pdf-parser.py shows the following.

![Alt text](/assets/images/2025/Leap/2-pdf1.png)

Notice that it contains an ObjStream, so append -O to show objects hidden in the object stream.

![Alt text](/assets/images/2025/Leap/3-pdf2.png)

According to the output, object 64 contains an embedded file, so let's dump the raw data.

{% highlight ruby %}
pdf-parser.py -O -o 64 -f -w -d object64.raw
{% endhighlight %}

![Alt text](/assets/images/2025/Leap/4-pdf3.png)

To verify the file type for the dumped file, run TrID on the file to see that it is an .XLS file (Microsoft Excel) file, meaning that you can run oledump on it. At this point we can ascertain that the PDF file contained an embedded .XLS document file, implying that the PDF file was the vehicle for the payload.

![Alt text](/assets/images/2025/Leap/5-trid.png)

Stream 67 looks like an equation exploit, which leads us to the involvement of CVE-2017–11882. Equation Editor is a tool that allows users to create content such as mathematical equations in a Word document. The CVE outlined as to how Equation Editor did not use DEP or ASLR, allowing for a buffer overflow to occur which threat actors used for RCE. Despite the CVE being originally recorded in 2017, it is continually utilized as a method of exploitation throughout malware samples today.

Examining the stream is accomplished using oledump.py.

{% highlight ruby %}
oledump.py -d -s 67 object64.raw > stream67.raw
{% endhighlight %}

![Alt text](/assets/images/2025/Leap/6-oledump.png)

Running the file command on stream67.raw reveals that it is a data type file, so we can run xorsearch -W on stream67.raw to see a GetEIP method at (258, 2E4, 36E, and 487) in the dumped stream. This is a strong indicator of shellcode being present in the file which aligns with CVE-2017–11882 behavior.

![Alt text](/assets/images/2025/Leap/7-xorsearch.png)

To view what the shellcode is/does, we will use scdbgc for emulation.

{% highlight ruby %}
scdbgc /f stream67.raw /s -1 /foff 258
{% endhighlight %}

![Alt text](/assets/images/2025/Leap/8-scdbgc.png)

The shellcode is using the URLDownloadToFileW() library to download vbc.exe from hxxp://103[.]167[.]85[.]227/r_220111 and drop it in C:\Users\Public as vbc.exe.

Attempting to access the link to download the file results in a dead link. However, with VirusTotal Premium (not paid shilling), scoping the IP allows for a download of the vbc.exe file with a match to the associated malware sample upload.

> Hash: 2a3f2ef4028d29252bc5b86701a71ba483d754c96884959f5419f015cb5dd5b2

Running peframe on the file notes that the hardcoded filename is gRxW.exe with bogus CompanyName, FileDescription, LegalCopyright and ProductName fields.

![Alt text](/assets/images/2025/Leap/9-peframe.png)

Coupling these results with yara-rules reveals that the file is a .NET-based executable.

![Alt text](/assets/images/2025/Leap/10-yara.png)

As the file does not appear to be packed, decompiling is trivial with dnSpy which reveals more information such as confirmation of what peframe provided.

![Alt text](/assets/images/2025/Leap/11-dnspy1.png)

Inside the FlyingThroughUniverse namespace is a function call to FormMain() and then InitializeComponent().

![Alt text](/assets/images/2025/Leap/12-dnspy2.png)

Scrolling through InitializeComponent() reveals some clues that may indicate decrypting of a BMP to drop another file/stage. The following bitmap files were associated with the executable: Ant, Moon, ovqj, SecondsHand, ShortHand.

![Alt text](/assets/images/2025/Leap/13-dnspy3.png)

I could be wrong, but it appears that ovqj will be decoded, converted to bytes, and then dynamically loaded into the address 0x0002DD00 as an executable.

![Alt text](/assets/images/2025/Leap/14-dnspy4.png)

Due to an unfortunate lack of further knowledge, my analysis of the .NET component stopped here as I attempted to set breakpoints to discover the decryption key for the bitmap with no success. However, I was able to determine with the behavior and IOCs discovered in my analysis that this executable is likely the new loader utilized in the recent Formbook campaign to kick start the next stage in the infection chain.

Thanks for reading!