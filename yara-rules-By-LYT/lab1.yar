rule Lab1
{
meta:
	description = "rules for Lab1 "
	date = "202x/xx/xx"
	author = "LYT"
strings:
	$a = "kerne132.dll" wide ascii
	$b = "127.26.152.13" wide ascii
	$c = "http://www.malwareanalysisbook.com" wide ascii
	$d = "wupdmgr" wide ascii
condition:
	any of them
}
