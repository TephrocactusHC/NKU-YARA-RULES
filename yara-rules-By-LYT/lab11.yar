rule Lab11
{
 meta:
 description = "rules for Lab11"
 date = "2021/12/5"
 strings:
 $a0 = "msgina32.dll"
 $a1 = "HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\CurrentVersion\\winlogon\\GinaDLL"
 $a2 = "msutil32.sys" 
 $a3 = "spoolvxx32.dll"
 $a4 = "billy@malwareanalysisbook.com"
 $a5 = "inet_epar32.dll"
 $a6 = "kernel64x.dll"
 $a7 = " zzz69806582" 
 condition:
 any of them
}