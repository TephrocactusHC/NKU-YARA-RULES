rule Lab13
{
 meta:
 description = "rules for Lab13"
 date = "2021/12/23"
 strings:
 $a = "http://www.practicalmalwareanalysis.com"
 condition:
 any of them
}
