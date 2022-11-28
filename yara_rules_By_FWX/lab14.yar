import "pe"

rule EXE {
	strings:
		$exe = "autobat.exe"
	condition:
		$exe
}

rule URL {
	strings:
		$Http = "http://" nocase
		$Https = "https://" nocase
	condition:
		$Http or $Https
}

rule EXIT {
	strings:
		$s = "exit"
	condition:
		$s
}

rule UserAgent {
	strings:
		$u = "User-Agent"
	condition:
		$u
}

rule Construct {
	strings:
		$s = /(%c)*/
	condition:
		$s
}