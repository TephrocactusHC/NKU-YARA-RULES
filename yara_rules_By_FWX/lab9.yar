import "pe"

rule UrlRequest {
	strings:
		$http = "http"
		$GET = "GET" nocase
		$com = /[a-zA-Z0-9_]*.com/
	condition:
		$http or $GET or $com
}

rule cmd {
	strings:
		$name = "cmd" nocase
	condition:
		$name 
}

rule EXE {
	strings:
		$exe = /[a-zA-Z0-9_]*.exe/
	condition:
		$exe
}

rule Regedit{
	strings:
		$system = "system32"
		$software = "SOFTWARE"
	condition:
		$system or $software 
}

rule DLL {
	strings:
		$dll = "DLL"
	condition:
		$dll
}

rule SOCKET {
	strings:
		$name = "Socket"
	condition:
		$name
}