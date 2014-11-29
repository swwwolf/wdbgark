# WinDBG Anti-RootKit extension

* [Preface](#preface)
* [Supported commands](#supported-commands)
* [Supported targets](#supported-targets)
* [Sources and build](#sources-and-build)
    * [Build using VS2012](#build-using-vs2012)
    * [Build using BUILD](#build-using-build)
* [Using](#using)
* [FAQ](#faq)
* [Help](#help)
* [License](#license)

## Preface

WDBGARK is an extension (dynamic library) for the [Microsoft Debugging Tools for Windows](http://msdn.microsoft.com/en-US/library/windows/hardware/ff551063).
It main purpose is to view and analyze anomalies in Windows kernel using kernel debugger. It is possible to view various system callbacks,
system tables, object types and so on. For more user-friendly view extension uses DML. For the most of the commands kernel-mode connection is required.
It's possible to use an extension with live kernel-mode debugging or with crash dump analysis (not all commands will work).

## Supported commands

* !wa_scan
* !wa_systemcb
* !wa_objtype
* !wa_objtypeidx
* !wa_callouts
* !wa_pnptable
* !wa_ssdt
* !wa_w32psdt
* !wa_checkmsr
* !wa_idt
* !wa_gdt

## Supported targets

* Microsoft Windows XP (x86)
* Microsoft Windows 2003 (x86/x64)
* Microsoft Windows Vista (x86/x64)
* Microsoft Windows 7 (x86/x64)
* Microsoft Windows 8.x (x86/x64)

BETAs/RCs are supported by design. IA64/ARM unsupported.

## Sources and build

Sources are organized as a Visual Studio 2012 solution, but it's possible to build using BUILD (prior WDK 8.x).

### Build using VS2012

* Download and install latest [WDK](http://msdn.microsoft.com/en-us/windows/hardware/hh852365).
* Define system environment variables (e.g. WDK 8.1).
    * _DBGSDK_INC_PATH_ = C:\WinDDK\8.1\Debuggers\inc
    * _DBGSDK_LIB_PATH_ = C:\WinDDK\8.1\Debuggers\lib
    * _WDKDIR_ = C:\WinDDK\8.1
* Choose solution configuration and platform.
* Build.

NOTE!

Post-build event is enabled for the debug builds. It automatically copies linked extension into WinDBG's plugins folder (e.g. x64 target:  
_"copy /B /Y $(OutDir)$(TargetName)$(TargetExt) $(WDKDIR)\Debuggers\x64\winext\$(TargetName)$(TargetExt)"_).

### Build using BUILD

* Choose and run build environment.
* Go to the project directory.
* build -cZg

## Using

* Build or download an extention.
* Make sure that [Visual C++ Redistributable for Visual Studio 2012](http://www.microsoft.com/en-US/download/details.aspx?id=30679) has already been installed.
* Copy an extension into WDK debugger's directory (e.g. WDK 8.1):
    * x64: C:\WinDDK\8.1\Debuggers\x64\winext\
    * x86: C:\WinDDK\8.1\Debuggers\x86\winext\
* Run WinDbg.
* Load extension using ".load wdbgark" (you can see loaded extensions with a ".chain" command).
* Run "!wdbgark.help" or "!wdbgark.wa_scan /reload".
* Have fun!

```
kd> .load wdbgark  
kd> .chain  
Extension DLL search Path:  
<...>  
Extension DLL chain:  
    wdbgark: image 1.5.0.0, API 1.0.0, built Thu Nov 27 00:18:33 2014
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
  !help          - Displays information on available extension commands
  !wa_callouts   - Output kernel-mode win32k callouts
  !wa_checkmsr   - Output system MSRs (live debug only!)
  !wa_idt        - Output processors IDT
  !wa_objtype    - Output kernel-mode object type(s)
  !wa_objtypeidx - Output kernel-mode ObTypeIndexTable
  !wa_pnptable   - Output kernel-mode nt!PlugPlayHandlerTable
  !wa_scan       - Scan system
  !wa_ssdt       - Output the System Service Descriptor Table
  !wa_systemcb   - Output kernel-mode registered callback(s)
  !wa_ver        - Shows extension version number
  !wa_w32psdt    - Output the Win32k Service Descriptor Table
!help <cmd> will give more information for a particular command
```

## FAQ

Q: What's the main purpose of the extension?  
A: Well, first is educational only. Second, for fun and profit.  

Q: Do you know about PyKd? I can script the whole Anti-Rootkit using Python.  
A: Yeah, i know, but C++ is much better.  

## Help

[Wiki](https://github.com/swwwolf/wdbgark/wiki) can help.

## License

This software is released under the GNU GPL v3 License, see COPYING.