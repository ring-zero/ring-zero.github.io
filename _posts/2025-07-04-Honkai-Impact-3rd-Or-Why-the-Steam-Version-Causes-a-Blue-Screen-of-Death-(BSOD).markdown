---
layout: default
title:  "Honkai Impact 3rd Or: Why the Steam Version Causes a Blue Screen of Death (BSOD)"
date:   2025-07-04 19:10:00 -0400
categories: debugging
---

Below are my findings through kernel debugging UniFairy.sys crashes related to the Steam version of Honkai Impact 3rd. I have already reported this to miYoHo and their development and engineering team have resolved the issue in a patch.

After a fresh install of the Steam version of Honkai Impact 3rd and upon launching the game, many players will crash with varying bugchecks, although usually SYSTEM_SERVICE_EXCEPTION (3B).

{% highlight ruby %}
Arg1: 00000000c0000005, Exception code that caused the bugcheck
{% endhighlight %}

Examining the first 0x3B bugcheck argument, the exception that was raised that caused the bugcheck was an access violation.

{% highlight ruby %}
Arg3: ffffe705998ee960, Address of the context record for the exception that caused the bugcheck

 0: kd> .cxr ffffe705998ee960
 rax=0000000000000000 rbx=000000000000047c rcx=0000000000000001
 rdx=0000000000000001 rsi=fffff80726301710 rdi=ffff9a80b7d303a0
 rip=fffff8072271141d rsp=ffffe705998ef360 rbp=0000000000000000
    r8=00000000ffffffff  r9=7fff880b041e3050 r10=7ffffffffffffffc
    r11=ffffe5f2f97cb000 r12=0000000000000004 r13=0000000000000001
    r14=000000005096377f r15=0000000000000005
    iopl=0         nv up ei ng nz na po nc
    cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050286
    UniFairy+0xb141d:
    fffff807`2271141d 48396818        cmp     qword ptr [rax+18h],rbp ds:002b:00000000`00000018=????????????????
{% endhighlight %}

Exploring the context record for the exception, UniFairy.sys is involved in the access violation.

{% highlight ruby %}
0: kd> !pte 002b
 VA 000000000000002b
 PXE at FFFFE5F2F97CB000 PPE at FFFFE5F2F9600000 PDE at FFFFE5F2C0000000 PTE at FFFFE58000000000
 contains 0A00000228D84867 contains 0A00000228B8E867 contains 0A00000234D92867 contains 0000000000000000
 pfn 228d84 - -DA - UWEV pfn 228b8e - -DA - UWEV pfn 234d92 - -DA - UWEV not valid
 {% endhighlight %}

 The memory at address 002b in the data segmentation process of the instruction is invalid. This is also precisely why the exception is being raised and the crash is occurring, because UniFairy.sys is a driver that requires kernel-level access, but the memory at address 002b is both writable AND executable. Consequently, this is violating Windows' Code integrity checking.

To further confirm this, enabling Driver Verifier with code integrity checks on UniFairy.sys will allow the kernel to catch the violation occurring and provide significantly more information at the time of the exception by calling the DRIVER_VERIFIER_DETECTED_VIOLATION (C4) bugcheck.

{% highlight ruby %}
Arg1: 0000000000002003, Code Integrity Issue: The image contains an executable and writable section.
{% endhighlight %}

The first argument of the bugcheck states that an image attempted to access kernel-space memory while being both executable and writeable.

{% highlight ruby %}
Arg2: ffffae86b027ed98, The image file name (Unicode string).
{% endhighlight %}

{% highlight ruby %}
6: kd> dS ffffae86b027ed98
 ffffae86`b027eea0 "UniFairy.sys"
{% endhighlight %}

UniFairy.sys was the image (driver) that was flagged by the kernel as attempting to access kernel-space memory while being both executable and writeable.

{% highlight ruby %}
0: kd> !lmi unifairy
 Loaded Module Info: [unifairy] 
 Module: UniFairy
 Base Address: fffff803774e0000
 Image Name: UniFairy.sys
{% endhighlight %}

!lmi can be used to locate the base address for the driver. This allows us to parse the section headers and see where the driver is executable and writable.

{% highlight ruby %}
0: kd> !dh -s fffff803774e0000
{% endhighlight %}

{% highlight ruby %}
SECTION HEADER #6
 INIT name
 C8E virtual size
 33000 virtual address
 E00 size of raw data
 2F600 file pointer to raw data
 0 file pointer to relocation table
 0 file pointer to line numbers
 0 number of relocations
 0 number of line numbers
 E2000020 flags
 Code
 Discardable
 (no align specified)
 Execute Read Write

SECTION HEADER #9
 .tvm0 name
 90000 virtual size
 36000 virtual address
 90000 size of raw data
 30A00 file pointer to raw data
 0 file pointer to relocation table
 0 file pointer to line numbers
 0 number of relocations
 0 number of line numbers
 E0000020 flags
 Code
 (no align specified)
 Execute Read Write
{% endhighlight %}

In both section headers #6 and #9, the UniFairy.sys is flagged as executable, readable, and writable.

{% highlight ruby %}
0: kd> kNL
 # Child-SP RetAddr Call Site
 00 ffffc882`de90d4a8 fffff803`607d9e34 nt!KeBugCheckEx
 01 ffffc882`de90d4b0 fffff803`603a8c25 nt!VerifierBugCheckIfAppropriate+0xe0
 02 ffffc882`de90d4f0 fffff803`607d0a40 nt!VfReportIssueWithOptions+0x101
 03 ffffc882`de90d540 fffff803`607e2ee7 nt!VfCheckImageCompliance+0x124
 04 ffffc882`de90d5c0 fffff803`607cd4aa nt!VfSuspectDriversLoadCallback+0x34f
 05 ffffc882`de90d610 fffff803`6055322e nt!VfDriverLoadImage+0x240a
 06 ffffc882`de90d650 fffff803`605527c3 nt!MiFinalizeDriverImage+0x16
 07 ffffc882`de90d680 fffff803`60552076 nt!MmLoadSystemImageEx+0x737
 08 ffffc882`de90d820 fffff803`605355cc nt!MmLoadSystemImage+0x26
 09 ffffc882`de90d860 fffff803`6057a0b7 nt!IopLoadDriver+0x23c
 0a ffffc882`de90da30 fffff803`600c4515 nt!IopLoadUnloadDriver+0x57
 0b ffffc882`de90da70 fffff803`60161855 nt!ExpWorkerThread+0x105
 0c ffffc882`de90db10 fffff803`6020a8f8 nt!PspSystemThreadStartup+0x55
 0d ffffc882`de90db60 00000000`00000000 nt!KiStartSystemThread+0x28
 {% endhighlight %}

 Dumping the callstack at the time of the crash shows that a worker thread is started in kernel-space to load a driver into memory. However, as verifier is enabled, it catches the loaded driver (UniFairy.sys) during a callback and raises the bugcheck for a code integrity violation.
 
Testing further, I downloaded and installed the standalone Honkai Impact 3rd from the official miYoHo website. With this standalone client, I was able to launch the game, install all assets, and play with no issues.

Thanks for reading!