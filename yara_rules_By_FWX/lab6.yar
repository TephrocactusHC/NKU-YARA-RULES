import "pe"

rule Message {
	strings:
		$ErrorM = "Error"
		$SuccessM = "Success"
		$Internet = "Internet"
	condition:
		$ErrorM or $SuccessM or $Internet 
}

rule MalURLRequest {
	strings:
		$Mal = "practicalmalwareanalysis"
		$Http = "http"
	condition:
		$Mal and $Http
}

rule EXE {
	strings:
		$exe = /[a-zA-Z0-9_]+.exe/
	condition:
		$exe
}

rule Regedit {
	strings:
		$run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
	condition:
		$run
}