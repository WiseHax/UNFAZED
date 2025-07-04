rule EXE_Contains_CMD
{
    strings:
        $cmd = "cmd.exe"
        $ps = "powershell"
    condition:
        any of them
}
