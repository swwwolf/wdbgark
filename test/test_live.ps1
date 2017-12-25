param (
	[string]$Bit = "x64",
	[string]$Log = $(throw "-log path is required."),
	[string]$Exe = $(throw "-exe name is required."),
	[string]$Script = $(throw "-script name is required.")
)
$WdkDir=${env:ProgramFiles(x86)}+"\Windows Kits\10\"
$Command='$$>a<'+$PSScriptRoot+"\"+$Script
$Dbg=$WdkDir+"Debuggers\"+$Bit+"\"+$Exe
& $Dbg -b -k com:pipe,port=\\.\pipe\com_1,resets=0,reconnect -logo "$Log" -c "$Command"