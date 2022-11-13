import "pe"
import "hash"

rule URLRequest {
 meta:
  description = "Maybe malware will request IP or URL"
 strings:
  $IPV4 = /((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])/
  $url = /^((ht|f)tps?):\/\/([\w\-]+(\.[\w\-]+)*\/)*[\w\-]+(\.[\w\-]+)*\/?(\?([\w\-\.,@?^=%&:\/~\+#]*)+)?/
  $dll = "WS2_32.dll"
  condition:
  ($IPV4 or $url) or $dll
}

rule FileRevise {
	strings:
		$CreateFile = /CreatFile[a-zA-Z]*/
		$CopyFile = /CopyFile[a-zA-Z]*/
		$WriteFile = "WriteFile"
		$MoveFile =/MoveFile[a-zA-Z]*/
	condition:
		$CreateFile or $CopyFile or $WriteFile or $MoveFile
}

rule Service {
	strings:
		$CreateService = /CreateService[a-zA-Z]*/ nocase
		$InternetOpen = /InternetOpen[a-zA-Z]*/
	condition:
		$CreateService or $InternetOpen
}

rule DownloadFile {
	strings:
		$URLDownload = /URLDownloadToFile[a-zA-Z]*/
	condition:
		$URLDownload
}

rule ReviseRegedit {
	strings:
		$KeyName = /HKEY(_CLASSES_ROOT|_CURRENT_USER|_USERS|_LOCAL_MACHINE|_CURRENT_CONFIG)/
		$Regedit = /software(\\[a-zA-Z]*)*/ nocase
		$HKLM = /HTLM(\\[a-zA-Z]*)*/
		$RegAPI = /Reg[a-zA-Z]*/
	condition:
		$KeyName or $Regedit or $HKLM or $RegAPI
}

rule OtherEXE {
	strings:
		$exe = /[a-zA-Z0-9_]+.exe/
	condition:
		$exe
}

rule Install {
	strings:
		$InstallAPI = /(i|I)nstall[a-zA-Z0-9]*/ nocase
		$unInstall = /(U|u)ninstall[a-zA-Z0-9]*/ nocase
	condition:
		$InstallAPI or $unInstall
}

rule Sleep {
	strings:
		$Sleep = "sleep" nocase
	condition:
		$Sleep
}