rule Lab12
{
 meta:
 description = "rules for Lab12"
 date = "2021/12/11"
 strings:
 $a0 = "LOCALIZATION"
 $a1 = "paticalmalwareanalysis.log，"
 $a2 = "wupdmgrd.exe" 
 $a3 = "http://www.practicalmalwareanalysis.com/updater.exe"
 condition:
 any of them
}