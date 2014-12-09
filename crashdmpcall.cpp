/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2014  Vyacheslav Rusakoff
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

/*
    Vista+. Look for IopLoadCrashdumpDriver(). It's just a table with pure pointers.
*/

#include <sstream>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"

EXT_COMMAND(wa_crashdmpcall, "Output kernel-mode nt!CrashdmpCallTable", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << "Displaying nt!CrashdmpCallTable" << endlout;

    if ( m_minor_build < VISTA_RTM_VER ) {
        out << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    unsigned __int64 offset = 0;

    if ( !GetSymbolOffset("nt!CrashdmpCallTable", true, &offset) ) {
        err << __FUNCTION__ << ": failed to find nt!CrashdmpCallTable" << endlerr;
        return;
    }

    out << "[+] nt!CrashdmpCallTable: " << std::hex << std::showbase << offset << endlout;

    std::unique_ptr<WDbgArkAnalyze> display(new WDbgArkAnalyze(WDbgArkAnalyze::AnalyzeTypeDefault));

    if ( !display->SetOwnerModule( "crashdmp" ) )
        warn << __FUNCTION__ ": SetOwnerModule failed" << endlwarn;

    display->PrintHeader();

    try {
        for ( int i = 2; i < 0x100; i++ ) {  // skip first two entries, they're system reserved
            ExtRemoteData crashdmp_call_table_entry(offset + i * m_PtrSize, m_PtrSize);

            if ( !crashdmp_call_table_entry.GetPtr() )  // last is null
                break;

            display->AnalyzeAddressAsRoutine(crashdmp_call_table_entry.GetPtr(), "", "");
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
    display->PrintFooter();
}
