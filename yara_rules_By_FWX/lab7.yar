import "pe"

rule UrlRequest {
	strings:
		$http = "http"
	condition:
		$http 
}

rule Explorer {
	strings:
		$name = "Internet Explorer"
	condition:
		$name 
}

rule kerne132 {
	strings:
		$dll_name = "kerne132.dll"
	condition:
		$dll_name 
}

rule EXE {
	strings:
		$exe = /[a-zA-Z0-9_]*.exe/
	condition:
		$exe
}

rule scanC {
	strings:
		$c = /C:./
	condition:
		$c
}
