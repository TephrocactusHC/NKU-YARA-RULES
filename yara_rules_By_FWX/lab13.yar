import "pe"

rule URL {
	strings:
		$Http = "http://" nocase
		$Https = "https://" nocase
		$www = "www."
	condition:
		$Http or $Https or $www
}

rule StandardBase64 {
	strings:
		$base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	condition:
		$base
}

rule ShellCmd {
	strings:
		$exe = "cmd.exe"
	condition:
		$exe
}