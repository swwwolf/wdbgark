param (
	[string]$Bit = "x64",
	[string]$Dump = $(throw "-dump path is required."),
	[string]$Log = $(throw "-log path is required.")
)
$WdkDir=${env:ProgramFiles(x86)}+"\Windows Kits\10\"
$Command='$$>a<'+$PSScriptRoot+'\wa_test_script.txt'
$WinDbg=$WdkDir+"Debuggers\"+$Bit+"\windbg.exe"
& $WinDbg -z "$Dump" -logo "$Log" -c "$Command"