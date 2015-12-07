/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2015  Vyacheslav Rusakoff
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

EXT_COMMAND(wa_ssdt, "Output the System Service Descriptor Table", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying nt!KiServiceTable" << endlout;

    uint64_t offset = 0;
    uint32_t limit  = 0;

    try {
        if ( !m_sym_cache->GetSymbolOffset("nt!KiServiceLimit", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find nt!KiServiceLimit" << endlerr;
            return;
        }

        out << wa::showplus << "nt!KiServiceLimit: " << std::hex << std::showbase << offset << endlout;

        ExtRemoteData ki_service_limit(offset, sizeof(limit));
        limit = ki_service_limit.GetUlong();

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
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    if ( !display->AddRangeWhiteList("nt") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    display->PrintHeader();

    try {
        for ( uint32_t i = 0; i < limit; i++ ) {
            if ( m_is_cur_machine64 ) {
                std::string routine_name = get_service_table_routine_name(m_system_ver->GetStrictVer(),
                                                                          KiServiceTable_x64,
                                                                          i);

                ExtRemoteData service_offset_full(offset + i * sizeof(int), sizeof(int));
                int service_offset = service_offset_full.GetLong();

                if ( m_system_ver->GetStrictVer() >= VISTA_RTM_VER )
                    service_offset >>= 4;
                else
                    service_offset &= ~MAX_FAST_REFS_X64;

                display->Analyze(offset + service_offset, routine_name, "");
                display->PrintFooter();
            } else {
                std::string routine_name = get_service_table_routine_name(m_system_ver->GetStrictVer(),
                                                                          KiServiceTable_x86,
                                                                          i);

                ExtRemoteData service_address(offset + i * m_PtrSize, m_PtrSize);
                display->Analyze(service_address.GetPtr(), routine_name, "");
                display->PrintFooter();
            }
        }
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

    std::unique_ptr<WDbgArkProcess> process_helper(new WDbgArkProcess);

    uint64_t set_eprocess = 0;

    if ( HasArg( "process" ) )
        set_eprocess = GetArgU64("process");
    else
        set_eprocess = process_helper->FindEProcessAnyGUIProcess();

    if ( !SUCCEEDED(process_helper->SetImplicitProcess(set_eprocess)) )
        throw ExtStatusException(S_OK, "failed to set process");

    uint64_t offset = 0;
    uint32_t limit  = 0;

    try {
        if ( !m_sym_cache->GetSymbolOffset("win32k!W32pServiceLimit", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find win32k!W32pServiceLimit" << endlerr;
            return;
        }

        out << wa::showplus << "win32k!W32pServiceLimit: " << std::hex << std::showbase << offset << endlout;

        ExtRemoteData w32_service_limit(offset, sizeof(limit));
        limit = w32_service_limit.GetUlong();

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
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    if ( !display->AddRangeWhiteList("win32k") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    display->PrintHeader();

    try {
        for ( uint32_t i = 0; i < limit; i++ ) {
            if ( m_is_cur_machine64 ) {
                std::string routine_name = get_service_table_routine_name(m_system_ver->GetStrictVer(),
                                                                          W32pServiceTable_x64,
                                                                          i);

                ExtRemoteData service_offset_full(offset + i * sizeof(int), sizeof(int));
                int service_offset = service_offset_full.GetLong();

                if ( m_system_ver->GetStrictVer() >= VISTA_RTM_VER )
                    service_offset >>= 4;
                else
                    service_offset &= ~MAX_FAST_REFS_X64;

                display->Analyze(offset + service_offset, routine_name, "");
                display->PrintFooter();
            } else {
                std::string routine_name = get_service_table_routine_name(m_system_ver->GetStrictVer(),
                                                                          W32pServiceTable_x86,
                                                                          i);

                ExtRemoteData service_address(offset + i * m_PtrSize, m_PtrSize);
                display->Analyze(service_address.GetPtr(), routine_name, "");
                display->PrintFooter();
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
