# WinDBG Anti-RootKit extension
[![Coverity Scan Build Status](https://scan.coverity.com/projects/3610/badge.svg)](https://scan.coverity.com/projects/3610)

* [Preface](#preface)
* [Supported commands](#supported-commands)
* [Supported targets](#supported-targets)
* [Sources and build](#sources-and-build)
    * [Build using VS2012](#build-using-vs2012)
    * [Build using BUILD](#build-using-build)
* [Using](#using)
* [FAQ](#faq)
* [Help](#help)
* [Whoami](#whoami)
* [License](#license)

## Preface

WDBGARK is an extension (dynamic library) for the [Microsoft Debugging Tools for Windows](http://msdn.microsoft.com/en-US/library/windows/hardware/ff551063).
It main purpose is to view and analyze anomalies in Windows kernel using kernel debugger. It is possible to view various system callbacks,
system tables, object types and so on. For more user-friendly view extension uses DML. For the most of commands kernel-mode connection is required.
Feel free to use extension with live kernel-mode debugging or with kernel-mode crash dump analysis (some commands will not work).
Public symbols are required, so use them, force to reload them, ignore checksum problems, prepare them before analysis and you'll be happy.

## Supported commands

* !wa_scan
* !wa_systemcb
* !wa_objtype
* !wa_objtypeidx
* !wa_callouts
* !wa_pnptable
* !wa_crashdmpcall
* !wa_ssdt
* !wa_w32psdt
* !wa_checkmsr
* !wa_idt
* !wa_gdt
* !wa_colorize

## Supported targets

* Microsoft Windows XP (x86)
* Microsoft Windows 2003 (x86/x64)
* Microsoft Windows Vista (x86/x64)
* Microsoft Windows 7 (x86/x64)
* Microsoft Windows 8.x (x86/x64)
* Microsoft Windows 10.x (theoretically)

Windows BETA/RC is supported by design, but read a few notes. First, i don't care about checked builds. Second, i don't care
if you don't have [symbols](http://msdn.microsoft.com/en-us/windows/hardware/gg463028.aspx) (public or private).
IA64/ARM is unsupported (and will not).

## Sources and build

Sources are organized as a Visual Studio 2012 solution.

### Build using VS2012

* Download and install latest [WDK](http://msdn.microsoft.com/en-us/windows/hardware/hh852365)
* Define system environment variables (e.g. WDK 8.1).
    * DBGSDK_INC_PATH = C:\WinDDK\8.1\Debuggers\inc
    * DBGSDK_LIB_PATH = C:\WinDDK\8.1\Debuggers\lib
    * WDKDIR = C:\WinDDK\8.1
* Choose solution configuration and platform.
* Build.

#### NOTE!

Post-build event is enabled for debug build. It automatically copies linked extension into WinDBG's plugins folder (e.g. x64 target:  
_"copy /B /Y $(OutDir)$(TargetName)$(TargetExt) $(WDKDIR)\Debuggers\x64\winext\$(TargetName)$(TargetExt)"_).

### Build using BUILD

Depricated.

## Using

* Download and install Debugging Tools from the [Microsoft WDK](http://msdn.microsoft.com/en-us/windows/hardware/hh852365) downloads page.
* [Build](#sources-and-build) or download the extention.
* Make sure that [Visual C++ Redistributable for Visual Studio 2012](http://www.microsoft.com/en-US/download/details.aspx?id=30679) has already been installed.
* Copy extension to the WDK debugger's directory (e.g. WDK 8.1):
    * x64: C:\WinDDK\8.1\Debuggers\x64\winext\
    * x86: C:\WinDDK\8.1\Debuggers\x86\winext\
* Start WinDBG.
* [Setup](http://support.microsoft.com/kb/311503/en-us) WinDBG to use Microsoft Symbol Server correctly or deal with them manually.
* Load extension by **.load wdbgark** (you can see loaded extensions with a **.chain** command).
* Execute **!wdbgark.help** for help or **!wdbgark.wa_scan /reload** for full system scan with symbols reloading.
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
  !help            - Displays information on available extension commands
  !wa_callouts     - Output kernel-mode win32k callouts
  !wa_checkmsr     - Output system MSRs (live debug only!)
  !wa_colorize     - Adjust WinDBG colors dynamically (prints info with no
                     parameters)
  !wa_crashdmpcall - Output kernel-mode nt!CrashdmpCallTable
  !wa_gdt          - Output processors GDT
  !wa_idt          - Output processors IDT
  !wa_objtype      - Output kernel-mode object type(s)
  !wa_objtypeidx   - Output kernel-mode ObTypeIndexTable
  !wa_pnptable     - Output kernel-mode nt!PlugPlayHandlerTable
  !wa_scan         - Scan system (execute all commands)
  !wa_ssdt         - Output the System Service Descriptor Table
  !wa_systemcb     - Output kernel-mode registered callback(s)
  !wa_ver          - Shows extension version number
  !wa_w32psdt      - Output the Win32k Service Descriptor Table
!help <cmd> will give more information for a particular command
```

## FAQ

Q: What's the main purpose of the extension?  
A: Well, first is educational only. Second, for fun and profit.  

Q: Do you know about PyKd? I can script the whole Anti-Rootkit using Python.  
A: Yeah, i know, but C++ is much better.  

## Help

[Wiki](https://github.com/swwwolf/wdbgark/wiki) can help.

## Whoami

* [LinkedIn profile](https://www.linkedin.com/in/vrusakov)
* [Blog](http://sww-it.ru/) (russian mostly)

## License

This software is released under the GNU GPL v3 License. See the [COPYING file](COPYING) for the full license text and
[this](http://www.gnu.org/licenses/gpl-faq.en.html#GPLPluginsInNF) small addition.