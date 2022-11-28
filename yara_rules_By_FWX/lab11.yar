import "pe"

rule EXE {
	strings:
		$exe = ".exe" nocase
	condition:
		$exe
}

rule DLL {
	strings:
		$dll = /[a-zA-Z0-9_]*.dll/
	condition:
		$dll
}

rule Wlx {
	strings:
		$WlxFuncs = /Wlx[a-zA-Z]*/
	condition:	
		$WlxFuncs 
}

rule Gina {
	strings:
		$name = "Gina"
	condition:
		$name
}

rule Regedit {
	strings:
		$system = "NT"
		$software = "SOFTWARE"
		$winlogon = "Winlogon"
	condition:
		$system or $software or $winlogon 
}

rule INI {
	strings:
		$name = /[a-zA-Z0-9_]*.ini/
	condition:
		$name
}

rule Service {
	strings:
		$start = "net start"
	condition:
		$start 
}

rule RCPT {
	strings:
		$name = "RCPT TO"
	condition:
		$name
}