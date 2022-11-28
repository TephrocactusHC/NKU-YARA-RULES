import "pe"

rule UrlRequest {
	strings:
		$http = "http"
		$com = /[a-zA-Z0-9_]*.com/
	condition:
		$http or $com
}

rule EXE {
	strings:
		$exe = /[a-zA-Z0-9_]*.exe/
	condition:
		$exe
}

rule Regedit {
	strings:
		$system = "Registry"
		$software = "SOFTWARE"
	condition:
		$system or $software 
}

rule DriverFile {
	strings:
		$name = ".sys"
	condition:
		$name
}

rule Device {
	strings:
		$name = "Device"
	condition:
		$name
}

rule Service {
	strings:
		$create = "CreateService"
		$start = "StartService"
	condition:
		$create or $start 
}

rule ResourceFile {
	strings:
		$name = ".rsrc"
	condition:
		$name
}