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

#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"

EXT_COMMAND(wa_objtypeidx, "Output kernel-mode ObTypeIndexTable", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << "Displaying nt!ObTypeIndexTable" << endlout;

    if ( m_minor_build < W7RTM_VER ) {
        out << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    unsigned __int64 offset = 0;

    if ( !GetSymbolOffset("nt!ObTypeIndexTable", true, &offset) ) {
        err << __FUNCTION__ << ": failed to find nt!ObTypeIndexTable" << endlerr;
        return;
    }

    out << "[+] nt!ObTypeIndexTable: " << std::hex << std::showbase << offset << endlout;

    std::unique_ptr<WDbgArkAnalyze> display(new (std::nothrow) WDbgArkAnalyze);
    std::stringstream tmp_stream;

    if ( !display )
        throw ExtStatusException(S_OK, "not enough memory");

    if ( !display->Init(&tmp_stream, WDbgArkAnalyze::AnalyzeTypeDefault) )
        throw ExtStatusException(S_OK, "display init failed");

    if ( !display->SetOwnerModule("nt") )
        warn << __FUNCTION__ ": SetOwnerModule failed" << endlwarn;

    display->PrintHeader();

    try {
        for ( int i = 2; i < 0x100; i++ ) {
            ExtRemoteData object_type_ptr(offset + i * m_PtrSize, m_PtrSize);

            if ( object_type_ptr.GetPtr() ) {
                ExtRemoteTyped object_type("nt!_OBJECT_TYPE", object_type_ptr.GetPtr(), false, NULL, NULL);

                if ( !SUCCEEDED(DirectoryObjectTypeCallback(this, object_type, reinterpret_cast<void*>(display.get()))) )
                    break;
            } else {
                break;
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
