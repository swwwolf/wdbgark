# WinDBG Anti-RootKit extension
[![Coverity Scan Build Status](https://scan.coverity.com/projects/3610/badge.svg)](https://scan.coverity.com/projects/3610)

* [Preface](#preface)
* [Requirements](#requirements)
* [Supported commands](#supported-commands)
* [Supported targets](#supported-targets)
* [Sources and build](#sources-and-build)
    * [Build using VS2017](#build-using-vs2017)
    * [Build using BUILD](#build-using-build)
    * [Build using CMD](#build-using-cmd)
* [Using](#using)
* [FAQ](#faq)
* [Help](#help)
* [Used code](#used-code)
* [Whoami](#whoami)
* [License](#license)

## Preface

[WDBGARK](https://github.com/swwwolf/wdbgark) is an extension (dynamic library) for the
[Microsoft Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/index).
It main purpose is to view and analyze anomalies in Windows kernel using kernel debugger. It is possible to view
various system callbacks, system tables, object types and so on. For more user-friendly view extension uses DML.
For the most of commands kernel-mode connection is required. Feel free to use extension with live kernel-mode debugging
or with kernel-mode crash dump analysis (some commands will not work). Public symbols are required, so use them, force
to reload them, ignore checksum problems, prepare them before analysis and you'll be happy.

## Requirements

* Microsoft Visual Studio 2017
* WDK and SDK for Windows 10, version 1709 (10.0.16299.0)
* Visual C++ Redistributable for Visual Studio 2017

## Supported commands

* [!wa_scan](https://github.com/swwwolf/wdbgark/wiki/!wa_scan)
* [!wa_systemcb](https://github.com/swwwolf/wdbgark/wiki/!wa_systemcb)
* [!wa_objtype](https://github.com/swwwolf/wdbgark/wiki/!wa_objtype)
* [!wa_objtypeidx](https://github.com/swwwolf/wdbgark/wiki/!wa_objtypeidx)
* [!wa_objtypecb](https://github.com/swwwolf/wdbgark/wiki/!wa_objtypecb)
* [!wa_callouts](https://github.com/swwwolf/wdbgark/wiki/!wa_callouts)
* [!wa_pnptable](https://github.com/swwwolf/wdbgark/wiki/!wa_pnptable)
* [!wa_crashdmpcall](https://github.com/swwwolf/wdbgark/wiki/!wa_crashdmpcall)
* [!wa_ssdt](https://github.com/swwwolf/wdbgark/wiki/!wa_ssdt)
* [!wa_w32psdt](https://github.com/swwwolf/wdbgark/wiki/!wa_w32psdt)
* [!wa_checkmsr](https://github.com/swwwolf/wdbgark/wiki/!wa_checkmsr)
* [!wa_idt](https://github.com/swwwolf/wdbgark/wiki/!wa_idt)
* [!wa_gdt](https://github.com/swwwolf/wdbgark/wiki/!wa_gdt)
* [!wa_haltables](https://github.com/swwwolf/wdbgark/wiki/!wa_haltables)
* [!wa_colorize](https://github.com/swwwolf/wdbgark/wiki/!wa_colorize)
* !wa_chknirvana
* !wa_eop
* !wa_cicallbacks
* !wa_ciinfo
* !wa_drvmajor
* !wa_lxsdt
* !wa_psppico
* !wa_systables
* !wa_apiset
* !wa_w32psdt
* !wa_w32psdtflt
* !wdrce_copyfile
* !wdrce_cpuid

## Supported targets

* Microsoft Windows XP (x86)
* Microsoft Windows 2003 (x86/x64)
* Microsoft Windows Vista (x86/x64)
* Microsoft Windows 7 (x86/x64)
* Microsoft Windows 8.x (x86/x64)
* Microsoft Windows 10 (x86/x64)

Multiple targets debugging is not supported!

Windows BETA/RC is supported by design, but read a few notes. First, i don't care about checked builds.
Second, i don't care if you don't have [symbols](https://developer.microsoft.com/en-us/windows/hardware/download-symbols)
(public or private). IA64/ARM is unsupported (and will not).

## Sources and build

Sources are organized as a Visual Studio 2017 solution.

### Build using VS2017

* Download and install latest [WDK](https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit)
* Select **Build -> Batch Build** from the menu and build dummypdb module (x86 and x64).
![Batch Build](https://raw.githubusercontent.com/swwwolf/wdbgark/master/images/batch_build.png)
* Choose solution configuration and platform for the main project.
* Build.

#### NOTE!

Post-build event is enabled for debug build. It automatically copies linked extension into WinDBG's plugins folder (e.g. x64 target:  
```"copy /B /Y "$(OutDir)$(TargetName)$(TargetExt)" "$(WindowsSdkDir)Debuggers\x64\winext\$(TargetName)$(TargetExt)"```).

### Build using BUILD

Deprecated.

### Build using CMD

Yeah, it's possible to build all the stuff using simple batch script.

* Make sure that you have already installed PowerShell at least version 3.0.
    * If not, then download and install [Windows Management Framework](http://www.microsoft.com/en-US/download/details.aspx?id=40855).
* Execute the [release_build.cmd](release_build.cmd) with a single parameter - a version.
* Voila! If there were no errors, the archive file will be created (e.g. wdbgark.X.Y.zip).
    * If something is wrong, check the path to the Visual Studio 2017 in the script and/or output log file (release_build.log).

## Using

* Download and install [Debugging Tools](https://developer.microsoft.com/en-us/windows/hardware/download-windbg).
* [Build](#sources-and-build) or [download](https://github.com/swwwolf/wdbgark/releases) the extention.
* Make sure that [Visual C++ Redistributable for Visual Studio 2017](https://www.visualstudio.com/en-us/productinfo/2017-redistribution-vs) has already been installed.
* Copy extension to the WDK debugger's directory (e.g. WDK 10):
    * x64: ```C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\```
    * x86: ```C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\winext\```
* Start WinDBG.
* [Setup](https://msdn.microsoft.com/en-us/library/windows/desktop/ee416588(v=vs.85).aspx) WinDBG to use Microsoft Symbol Server correctly or deal with them manually.
* Load extension by **.load wdbgark** (you can see loaded extensions with a **.chain** command).
* Execute **!wdbgark.help** for help or **!wdbgark.wa_scan** for a full system scan.
* Have fun!

```
2: kd> .load wdbgark
2: kd> .chain
Extension DLL search Path:
<...>
Extension DLL chain:
    wdbgark: image 2.5.0.0, API 2.5.0, built Fri Oct 20 17:54:03 2017
        [path: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\wdbgark.dll]
    dbghelp: image 10.0.16299.15, API 10.0.6, 
        [path: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll]
    ext: image 10.0.16299.15, API 1.0.0, 
        [path: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\ext.dll]
    exts: image 10.0.16299.15, API 1.0.0, 
        [path: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\WINXP\exts.dll]
    kext: image 10.0.16299.15, API 1.0.0, 
        [path: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\kext.dll]
    kdexts: image 10.0.16299.15, API 1.0.0, 
        [path: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\WINXP\kdexts.dll]
2: kd> !wdbgark.help
Commands for C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\wdbgark.dll:
  !help            - Displays information on available extension commands
  !wa_apiset       - Output user-mode and/or kernel-mode ApiSet map
  !wa_callouts     - Output kernel-mode win32k callouts
  !wa_checkmsr     - Output system MSRs (live debug only!)
  !wa_chknirvana   - Checks processes for Hooking Nirvana instrumentation
  !wa_cicallbacks  - Output kernel-mode nt!g_CiCallbacks or nt!SeCiCallbacks
  !wa_ciinfo       - Output Code Integrity information
  !wa_colorize     - Adjust WinDBG colors dynamically (prints info with no
                     parameters)
  !wa_crashdmpcall - Output kernel-mode nt!CrashdmpCallTable
  !wa_drvmajor     - Output driver(s) major table
  !wa_eop          - Checks processes for Elevation of Privilege
  !wa_gdt          - Output processors GDT
  !wa_haltables    - Output kernel-mode HAL tables: nt!HalDispatchTable,
                     nt!HalPrivateDispatchTable, nt!HalIommuDispatchTable
  !wa_idt          - Output processors IDT
  !wa_lxsdt        - Output the Linux Subsystem Service Descriptor Table
  !wa_objtype      - Output kernel-mode object type(s)
  !wa_objtypecb    - Output kernel-mode callbacks registered with
                     ObRegisterCallbacks
  !wa_objtypeidx   - Output kernel-mode nt!ObTypeIndexTable
  !wa_pnptable     - Output kernel-mode nt!PlugPlayHandlerTable
  !wa_psppico      - Output kernel-mode Pico tables
  !wa_scan         - Scan system (execute all commands)
  !wa_ssdt         - Output the System Service Descriptor Table
  !wa_systables    - Output various kernel-mode system tables
  !wa_systemcb     - Output kernel-mode registered callback(s)
  !wa_ver          - Shows extension version number
  !wa_w32psdt      - Output the Win32k Service Descriptor Table
  !wa_w32psdtflt   - Output the Win32k Service Descriptor Table Filter
  !wdrce_copyfile  - Copy file (live debug only!)
  !wdrce_cpuid     - Execute CPUID instruction (live debug only!)
!help <cmd> will give more information for a particular command
```

## FAQ

Q: What is the main purpose of the extension?  
A: Well, first is educational only. Second, for fun and profit.  

Q: Do you know about PyKd? I can script the whole Anti-Rootkit using Python.  
A: Yeah, i know, but C++ is much better.  

Q: Where is version 1.0?  
A: Lost in space of Google Code.  

Q: When did the project start?  
A: February 2013 on Google Code.  

Q: What version should i use?  
A: Please use x64 version only. In the era of x64 i dunno why the heck you may need to use x86 version. x64 WinDBG is 
able to debug both x86 and x64. Host OS bitness is the only limitation.  

Q: How can i help?  
A: Spread a word. Report issues and feature requests. I'm open for any suggestions. Thanks!  

Q: What kind of memory dump is better to use with an extension?  
A: Complete memory dump.  

Q: How to report an issue?  
A: Feel free to report an issue using GitHub or email to me directly, but please, attach complete memory crash dump file.  

## Help

[Wiki](https://github.com/swwwolf/wdbgark/wiki) can help.

## Used code

* [BPrinter](https://github.com/dattanchu/bprinter). BSD License.
* [Udis86](https://github.com/vmt/udis86). Simplified BSD License.

## Whoami

* [LinkedIn profile](https://www.linkedin.com/in/vrusakov)
* [Blog](https://sww-it.ru/)

## License

This software is released under the GNU GPL v3 License. See the [COPYING file](COPYING) for the full license text and
[this](http://www.gnu.org/licenses/gpl-faq.en.html#GPLPluginsInNF) small addition.
