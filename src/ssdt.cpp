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

    out << "Displaying nt!KiServiceTable" << endlout;

    unsigned __int64 offset = 0;
    unsigned __int32 limit  = 0;

    try {
        if ( !GetSymbolOffset("nt!KiServiceLimit", true, &offset) ) {
            err << __FUNCTION__ << ": failed to find nt!KiServiceLimit" << endlerr;
            return;
        }

        out << "nt!KiServiceLimit: " << std::hex << std::showbase << offset << endlout;

        ExtRemoteData ki_service_limit(offset, sizeof(limit));
        limit = ki_service_limit.GetUlong();

        if ( !limit ) {
            err << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << "ServiceLimit:      " << std::hex << std::showbase << limit << endlout;

        if ( !GetSymbolOffset("nt!KiServiceTable", true, &offset) ) {
            err << __FUNCTION__ << ": failed to find nt!KiServiceTable" << endlerr;
            return;
        }

        out << "nt!KiServiceTable: " << std::hex << std::showbase << offset << endlout;
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    std::unique_ptr<WDbgArkAnalyze> display(new WDbgArkAnalyze(WDbgArkAnalyze::AnalyzeTypeDefault));

    if ( !display->SetOwnerModule("nt") )
        warn << __FUNCTION__ ": SetOwnerModule failed" << endlwarn;

    display->PrintHeader();

    try {
        for ( unsigned __int32 i = 0; i < limit; i++ ) {
            if ( m_is_cur_machine64 ) {
                std::string routine_name = get_service_table_routine_name(m_minor_build, KiServiceTable_x64, i);

                ExtRemoteData service_offset_full(offset + i * sizeof(int), sizeof(int));
                int service_offset = service_offset_full.GetLong();

                if ( m_minor_build >= VISTA_RTM_VER )
                    service_offset >>= 4;
                else
                    service_offset &= ~MAX_FAST_REFS_X64;

                display->AnalyzeAddressAsRoutine(offset + service_offset, routine_name, "");
                display->PrintFooter();
            } else {
                std::string routine_name = get_service_table_routine_name(m_minor_build, KiServiceTable_x86, i);

                ExtRemoteData service_address(offset + i * m_PtrSize, m_PtrSize);
                display->AnalyzeAddressAsRoutine(service_address.GetPtr(), routine_name, "");
                display->PrintFooter();
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
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

    out << "Displaying win32k!W32pServiceTable" << endlout;

    std::unique_ptr<WDbgArkProcess> process_helper(new WDbgArkProcess);

    unsigned __int64 set_eprocess = 0;

    if ( HasArg( "process" ) )
        set_eprocess = GetArgU64("process");
    else
        set_eprocess = process_helper->FindEProcessAnyGUIProcess();

    if ( !SUCCEEDED(process_helper->SetImplicitProcess(set_eprocess)) )
        throw ExtStatusException(S_OK, "failed to set process");

    unsigned __int64 offset = 0;
    unsigned __int32 limit  = 0;

    try {
        if ( !GetSymbolOffset("win32k!W32pServiceLimit", true, &offset) ) {
            err << __FUNCTION__ << ": failed to find win32k!W32pServiceLimit" << endlerr;
            return;
        }

        out << "win32k!W32pServiceLimit: " << std::hex << std::showbase << offset << endlout;

        ExtRemoteData w32_service_limit(offset, sizeof(limit));
        limit = w32_service_limit.GetUlong();

        if ( !limit ) {
            err << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << "ServiceLimit:            " << std::hex << std::showbase << limit << endlout;

        if ( !GetSymbolOffset("win32k!W32pServiceTable", true, &offset) ) {
            err << __FUNCTION__ << ": failed to find win32k!W32pServiceTable" << endlerr;
            return;
        }

        out << "win32k!W32pServiceTable: " << std::hex << std::showbase << offset << endlout;
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    std::unique_ptr<WDbgArkAnalyze> display(new WDbgArkAnalyze(WDbgArkAnalyze::AnalyzeTypeDefault));

    if ( !display->SetOwnerModule( "win32k" ) )
        warn << __FUNCTION__ ": SetOwnerModule failed" << endlwarn;

    display->PrintHeader();

    try {
        for ( unsigned __int32 i = 0; i < limit; i++ ) {
            if ( m_is_cur_machine64 ) {
                std::string routine_name = get_service_table_routine_name(m_minor_build, W32pServiceTable_x64, i);

                ExtRemoteData service_offset_full(offset + i * sizeof(int), sizeof(int));
                int service_offset = service_offset_full.GetLong();

                if ( m_minor_build >= VISTA_RTM_VER )
                    service_offset >>= 4;
                else
                    service_offset &= ~MAX_FAST_REFS_X64;

                display->AnalyzeAddressAsRoutine(offset + service_offset, routine_name, "");
                display->PrintFooter();
            } else {
                std::string routine_name = get_service_table_routine_name(m_minor_build, W32pServiceTable_x86, i);

                ExtRemoteData service_address(offset + i * m_PtrSize, m_PtrSize);
                display->AnalyzeAddressAsRoutine(service_address.GetPtr(), routine_name, "");
                display->PrintFooter();
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
