rule Lab3
{
meta:
	description = "rules for Lab3"
	date = "202x/xx/xx"
strings:
	$a = "vmx32to64" wide ascii
	$b = "serve.html" wide ascii
	$c = "http://www.malwareanalysisbook.com" wide ascii
	$d = "svchost" wide ascii
	$e = "practicalmalwareanalysis.log" wide ascii
condition:
	any of them
}