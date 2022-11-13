The author is GD and LQY.

// 检查文件大小和是否为PE文件
private global rule FileSizeAndIsPE {
    condition: 
        filesize < 150KB and
        uint16(0)== 0x5A4D and  // MZ 头
        uint32(uint32(0x3C))== 0x00004550   // PE 头
}

rule get {
    strings:
        $get = "gethostbyname"
        $url = "pics.practicalmalwareanalysis.com"
        $ver = "VersionInformation.dwPlatformId"
        $version = "VersionInformation.dwMajorVersion"
        $a = "malloc"
        $b = "send"
        $c = "free"
    condition:
        ($get or $url or $ver or $version or $a or $b or $c) and FileSizeAndIsPE
}

rule remote_shell_session {
    strings:
        $remote = "Remote Shell Session"
    condition:
        $remote and FileSizeAndIsPE
}

rule get_systemlang_process {
    strings:
        $lang = "GetSystemDefaultLangID"
        $process = "CreateToolhelp32Snapshot"
    condition:
        ($lang or $process) and FileSizeAndIsPE
}

rule sleep {
    strings:
        $sleep = "sleep" nocase
    condition:
        $sleep and FileSizeAndIsPE
}

rule Internet {
    strings:
        $a = "IPPROTO_TCP"
        $b = "SOCK_STREAM"
        $c = "AF_INET"
    condition:
        ($a or $b or $c) and FileSizeAndIsPE
}

rule VM {
    strings:
        $VM = "VMXh"
    condition:
        $VM and FileSizeAndIsPE
}

rule xdoor {
    strings:
        $a = "xdoor is this backdoor, string decoded for practical Malware Analysis Lab"
    condition:
        $a and FileSizeAndIsPE
}
