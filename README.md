# WinDBG Anti-RootKit extension

* [Preface](#preface)
* [Latest changes](#latest-changes)
* [Supported targets](#supported-targets)
* [Sources and build](#sources-and-build)
    * [Build using VS2010/VS2012](#build-using-vs2010vs2012)
    * [Build using BUILD](#build-using-build)
* [Using](#using)

## Preface

WDBGARK is an extension (dynamic library) for the Microsoft Debugging Tools for Windows (see http://msdn.microsoft.com/en-US/library/windows/hardware/ff551063). It main purpose is to view and analyze anomalies in Windows kernel using kernel debugger.

It is possible to view various system callbacks, system tables, object types and so on. For more user-friendly view extension uses DML.

For the most of the commands kernel-mode connection is required. It's possible to use an extension with live kernel-mode debugging or with crash dump analysis (not all commands will work).

## Latest changes

Supported commands:

* !scan
* !systemcb
* !objtype
* !objtypeidx
* !callouts
* !pnptable
* !ssdt
* !w32psdt
* !checkmsr
* !idt
* !gdt

## Supported targets

* Microsoft Windows XP [x86/]
* Microsoft Windows 2003 [x86/x64]
* Microsoft Windows Vista [x86/x64]
* Microsoft Windows 7 [x86/x64]
* Microsoft Windows 8.x [x86/x64]

BETAs/RCs are supported by design. IA64/ARM unsupported.

## Sources and build

Sources are organized as a Visual Studio 2012 (2010) solution, but it's possible to build using BUILD (prior WDK 8.x).

### Build using VS2010/VS2012

* Download and install latest WDK (http://msdn.microsoft.com/en-us/windows/hardware/hh852365)
* Define system environment variables (e.g. WDK 8.1)
    * _DBGSDK_INC_PATH_ = C:\WinDDK\8.1\Debuggers\inc
    * _DBGSDK_LIB_PATH_ = C:\WinDDK\8.1\Debuggers\lib
    * _WDKDIR_ = C:\WinDDK\8.1
* Choose solution configuration and platform
* Build

NOTE!

Post-build event is enabled for the debug builds. It automatically copies linked extension into WinDBG's plugins folder (e.g. x64 target: _"copy /B /Y $(OutDir)$(TargetName)$(TargetExt) $(WDKDIR)\Debuggers\x64\winext\$(TargetName)$(TargetExt)"_).

### Build using BUILD

* Choose and run build environment
* Go to the project directory
* build -cZg

## Using

* Build or download an extention
* Copy an extension into right WDK debugger's directory (e.g. WDK 8.1):
    * x64: C:\WinDDK\8.1\Debuggers\x64\winext\
    * x86: C:\WinDDK\8.1\Debuggers\x86\winext\
* Run WinDbg
* Load extension using ".load wdbgark" (you can see all loaded extensions with a ".chain" command)
* Run "!wdbgark.help" or "!wdbgark.scan"

```
kd> .load wdbgark  
kd> .chain  
Extension DLL search Path:  
<...>  
Extension DLL chain:  
    wdbgark: image 1.0.0.0, API 1.0.0, built Mon Apr 07 11:44:48 2014  
        [path: C:\WinDDK\8.1\Debuggers\x64\winext\wdbgark.dll]
    WdfKd.dll: image 6.3.9600.16384, API 1.0.0, built Thu Aug 22 15:18:45 2013
        [path: C:\WinDDK\8.1\Debuggers\x64\winext\WdfKd.dll]
    dbghelp: image 6.3.9600.16384, API 6.3.6, built Thu Aug 22 15:25:28 2013
        [path: C:\WinDDK\8.1\Debuggers\x64\dbghelp.dll]
    ext: image 6.3.9600.16384, API 1.0.0, built Thu Aug 22 15:39:42 2013
        [path: C:\WinDDK\8.1\Debuggers\x64\winext\ext.dll]
    exts: image 6.3.9600.16384, API 1.0.0, built Thu Aug 22 15:32:48 2013
        [path: C:\WinDDK\8.1\Debuggers\x64\WINXP\exts.dll]
    kext: image 6.3.9600.16384, API 1.0.0, built Thu Aug 22 15:34:26 2013
        [path: C:\WinDDK\8.1\Debuggers\x64\winext\kext.dll]
    kdexts: image 6.3.9600.16384, API 1.0.0, built Thu Aug 22 15:34:37 2013
        [path: C:\WinDDK\8.1\Debuggers\x64\WINXP\kdexts.dll]
```
```
kd> !wdbgark.help
Commands for C:\WinDDK\8.1\Debuggers\x64\winext\wdbgark.dll:
  !callouts   - Output the kernel-mode win32k callouts
                
  !help       - Displays information on available extension commands
  !objtype    - Output the kernel-mode object type(s)
                
  !objtypeidx - Output the kernel-mode ObTypeIndexTable
                
  !pnptable   - Output the kernel-mode nt!PlugPlayHandlerTable
                
  !scan       - Run all commands
                
  !ssdt       - Output the System Service Descriptor Table
                
  !systemcb   - Output the kernel-mode OS registered callback(s)
                
  !ver        - Shows version number of the extension.
                
  !w32psdt    - Output the Win32k Service Descriptor Table
                
!help <cmd> will give more information for a particular command
```

## FAQ

Q: What is the purpose of the extension?  
A: Well, first is educational only. Second, for fun and profit.  

Q: Do you know about PyKd? I can script the whole Anti-Rootkit using Python.  
A: Yeah, i know, but C++ is much better.  
