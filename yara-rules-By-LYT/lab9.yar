rule Lab9
{
 meta:
 description = "rules for Lab9"
 date = "2021/11/14"
 strings:
 $a0 = "HKLM\\Software\\Microsoft \\XPS\\Configuration" 
 $a1 = "http://www.malwareanalysisbook.com" 
 $a2 = "ocl.exe" 
 $a3 = "1qaz2wsx3edc" 
 $a4 = "practicalmalwareanalysis.com" 
 $a5 = "DLL1.dll" 
 $a6 = "DLL2.dll" 
 $a7 = "DLL3.dll" 
 $a8 = "mystery data" 
 $a9 = "ping www.malwareanalysisbook.com"
 condition:
 any of them
}
}
