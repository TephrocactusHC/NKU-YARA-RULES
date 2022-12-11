rule Lab10
{
 meta:
 description = "rules for Lab10"
 date = "2021/11/25"
 strings:
 $a0 = " HKLM\\SOFTWARE\\Microsoft\\Cryptography\\RNG\\Seed "
 $a1 = "http://www.malwareanalysisbook.com/ad.html" 
 $a2 =
"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProf
ile"
 $a3 =
"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfil
e"
 $a4 = "Mlwx486.sys" 
 condition:
any of them
}