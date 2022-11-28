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

rule WriteFile {
	strings:
		$name = "WriteFile"
	condition:	
		$name 
}

rule SetHook {
	strings:
		$SetFunc = "SetWindowsHookExA"
		$UnFunc = "UnhookWindowsHookEx"
	condition:
		$SetFunc or $UnFunc 
}

rule URL {
	strings:
		$Http = "http://" nocase
		$Https = "https://" nocase
	condition:
		$Http or $Https
}

rule UseSource {
	strings:
		$find = "FineResourceA"
		$load = "LoadResource"
		$size = "SizeofResource"
	condition:
		$find or $load or $size
}