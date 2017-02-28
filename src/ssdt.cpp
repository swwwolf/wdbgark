/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2017  Vyacheslav Rusakoff
    * 
    * This program is free software: you can redistribute it and/or modify
    * it under the terms of the GNU General Public License as published by
    * the Free Software Foundation, either version 3 of the License, or
    * (at your option) any later version.
    * 
    * This program is distributed in the hope that it will be useful,
    * but WITHOUT ANY WARRANTY; without even the implied warranty of
    * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    * GNU General Public License for more details.
    * 
    * You should have received a copy of the GNU General Public License
    * along with this program.  If not, see <http://www.gnu.org/licenses/>.

    * This work is licensed under the terms of the GNU GPL, version 3.  See
    * the COPYING file in the top-level directory.
*/

#include <string>
#include <memory>

#include "wdbgark.hpp"
#include "sdt_w32p.hpp"
#include "process.hpp"
#include "analyze.hpp"

namespace wa {

void DisplayServiceTable(const uint64_t offset,
                         const uint32_t limit,
                         const ServiceTableType type,
                         const uint32_t build,
                         const std::unique_ptr<WDbgArkAnalyzeBase> &display) {
    for ( uint32_t i = 0; i < limit; i++ ) {
        uint64_t address = 0;

        if ( g_Ext->IsCurMachine64() ) {
            int service_offset = ExtRemoteData(offset + i * sizeof(int), sizeof(int)).GetLong();

            if ( build >= VISTA_RTM_VER )
                service_offset >>= 4;
            else
                service_offset &= ~MAX_FAST_REFS_X64;

            address = offset + service_offset;
        } else {
            address = ExtRemoteData(offset + i * g_Ext->m_PtrSize, g_Ext->m_PtrSize).GetPtr();
        }

        display->Analyze(address, get_service_table_routine_name(build, type, i));
        display->PrintFooter();
    }
}

EXT_COMMAND(wa_ssdt, "Output the System Service Descriptor Table", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying nt!KiServiceTable" << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeSDT);

    if ( !display->AddRangeWhiteList("nt") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    try {
        uint64_t offset = 0;

        if ( !m_sym_cache->GetSymbolOffset("nt!KiServiceLimit", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find nt!KiServiceLimit" << endlerr;
            return;
        }

        out << wa::showplus << "nt!KiServiceLimit: " << std::hex << std::showbase << offset << endlout;

        uint32_t limit = ExtRemoteData(offset, sizeof(limit)).GetUlong();

        if ( !limit ) {
            err << wa::showminus << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << wa::showplus << "ServiceLimit:      " << std::hex << std::showbase << limit << endlout;

        if ( !m_sym_cache->GetSymbolOffset("nt!KiServiceTable", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find nt!KiServiceTable" << endlerr;
            return;
        }

        out << wa::showplus << "nt!KiServiceTable: " << std::hex << std::showbase << offset << endlout;

        display->PrintHeader();
        DisplayServiceTable(offset,
                            limit,
                            m_is_cur_machine64 ? KiServiceTable_x64 : KiServiceTable_x86,
                            m_system_ver->GetStrictVer(),
                            display);
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

EXT_COMMAND(wa_w32psdt,
            "Output the Win32k Service Descriptor Table",
            "{process;e64;o;process,Any GUI EPROCESS address (use explorer.exe)}") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying win32k!W32pServiceTable" << endlout;

    auto process_helper = std::make_unique<WDbgArkProcess>();
    uint64_t set_eprocess = 0;

    if ( HasArg("process") )
        set_eprocess = GetArgU64("process");
    else
        set_eprocess = process_helper->FindEProcessAnyGUIProcess();

    if ( !SUCCEEDED(process_helper->SetImplicitProcess(set_eprocess)) )
        throw ExtStatusException(S_OK, "failed to set process");

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeSDT);

    if ( !display->AddRangeWhiteList("win32k") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    try {
        uint64_t offset = 0;

        if ( !m_sym_cache->GetSymbolOffset("win32k!W32pServiceLimit", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find win32k!W32pServiceLimit" << endlerr;
            return;
        }

        out << wa::showplus << "win32k!W32pServiceLimit: " << std::hex << std::showbase << offset << endlout;

        uint32_t limit = ExtRemoteData(offset, sizeof(limit)).GetUlong();

        if ( !limit ) {
            err << wa::showminus << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << wa::showplus << "ServiceLimit:            " << std::hex << std::showbase << limit << endlout;

        if ( !m_sym_cache->GetSymbolOffset("win32k!W32pServiceTable", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find win32k!W32pServiceTable" << endlerr;
            return;
        }

        out << wa::showplus << "win32k!W32pServiceTable: " << std::hex << std::showbase << offset << endlout;

        display->PrintHeader();
        DisplayServiceTable(offset,
                            limit,
                            m_is_cur_machine64 ? W32pServiceTable_x64 : W32pServiceTable_x86,
                            m_system_ver->GetStrictVer(),
                            display);
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

EXT_COMMAND(wa_w32psdtflt,
            "Output the Win32k Service Descriptor Table Filter",
            "{process;e64;o;process,Any GUI EPROCESS address (use explorer.exe)}") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying win32k!W32pServiceTableFilter" << endlout;

    if ( m_system_ver->GetStrictVer() <= W10TH2_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    auto process_helper = std::make_unique<WDbgArkProcess>();
    uint64_t set_eprocess = 0;

    if ( HasArg("process") )
        set_eprocess = GetArgU64("process");
    else
        set_eprocess = process_helper->FindEProcessAnyGUIProcess();

    if ( !SUCCEEDED(process_helper->SetImplicitProcess(set_eprocess)) )
        throw ExtStatusException(S_OK, "failed to set process");

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeSDT);

    if ( !display->AddRangeWhiteList("win32k") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    try {
        uint64_t offset = 0;

        if ( !m_sym_cache->GetSymbolOffset("win32k!W32pServiceLimitFilter", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find win32k!W32pServiceLimitFilter" << endlerr;
            return;
        }

        out << wa::showplus << "win32k!W32pServiceLimitFilter: " << std::hex << std::showbase << offset << endlout;

        uint32_t limit = ExtRemoteData(offset, sizeof(limit)).GetUlong();

        if ( !limit ) {
            err << wa::showminus << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << wa::showplus << "ServiceLimit:                  " << std::hex << std::showbase << limit << endlout;

        if ( !m_sym_cache->GetSymbolOffset("win32k!W32pServiceTableFilter", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find win32k!W32pServiceTableFilter" << endlerr;
            return;
        }

        out << wa::showplus << "win32k!W32pServiceTableFilter: " << std::hex << std::showbase << offset << endlout;

        display->PrintHeader();
        DisplayServiceTable(offset,
                            limit,
                            m_is_cur_machine64 ? W32pServiceTableFilter_x64 : W32pServiceTableFilter_x86,
                            m_system_ver->GetStrictVer(),
                            display);
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    } catch ( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

uint32_t GetLxpSyscallsLimit() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() )
        return 0;

    if ( system_ver.GetStrictVer() >= W10RS1_VER )
        return 0x138;

    return 0;
}

uint32_t GetLxpSyscallsRoutineDelta() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() )
        return 0;

    if ( system_ver.GetStrictVer() >= W10RS1_VER )
        return 0x38;

    return 0;
}

EXT_COMMAND(wa_lxsdt, "Output the Linux Subsystem Service Descriptor Table", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying lxcore!LxpSyscalls" << endlout;

    if ( m_system_ver->GetStrictVer() <= W10TH2_VER || !m_is_cur_machine64 ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    if ( FAILED(m_Symbols3->GetModuleByModuleName2("lxcore", 0UL, 0UL, nullptr, nullptr)) ) {
        out << wa::showplus << __FUNCTION__ << ": LXCORE module not found" << endlout;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeSDT);

    if ( !display->AddRangeWhiteList("lxcore") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    try {
        uint32_t limit = GetLxpSyscallsLimit();

        if ( !limit ) {
            err << wa::showminus << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << wa::showplus << "ServiceLimit:       " << std::hex << std::showbase << limit << endlout;

        uint64_t offset = 0;

        if ( !m_sym_cache->GetSymbolOffset("lxcore!LxpSyscalls", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find lxcore!LxpSyscalls" << endlerr;
            return;
        }

        out << wa::showplus << "lxcore!LxpSyscalls: " << std::hex << std::showbase << offset << endlout;

        display->PrintHeader();

        walkresType output_list;
        WalkAnyTable(offset, 0, limit, GetLxpSyscallsRoutineDelta(), "", &output_list, false, true);

        uint32_t i = 0;

        for ( const auto &walk_info : output_list ) {
            display->Analyze(walk_info.address,
                             get_service_table_routine_name(m_system_ver->GetStrictVer(), LxpSyscalls_x64, i));
            display->PrintFooter();
            i++;
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    } catch ( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
