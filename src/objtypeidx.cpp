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

#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"
#include "whitelist.hpp"
#include "memtable.hpp"

namespace wa {

EXT_COMMAND(wa_objtypeidx, "Output kernel-mode nt!ObTypeIndexTable", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    out << wa::showplus << "Displaying nt!ObTypeIndexTable" << endlout;

    if ( m_system_ver->GetStrictVer() <= VISTA_SP2_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    WDbgArkMemTable table(m_sym_cache, "nt!ObTypeIndexTable");

    if ( table.IsValid() ) {
        table.SetTableSkipStart(2 * m_PtrSize);
        table.SetTableCount(0x100);
        table.SetRoutineDelta(m_PtrSize);
        table.SetBreakOnNull(true);
    } else {
        err << wa::showminus << __FUNCTION__ << ": failed to find nt!ObTypeIndexTable" << endlerr;
        return;
    }

    out << wa::showplus << "nt!ObTypeIndexTable: " << std::hex << std::showbase << table.GetTableStart() << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeObjType);

    if ( !display->AddRangeWhiteList("nt") ) {
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;
    }

    display->SetWhiteListEntries(GetObjectTypesWhiteList());
    display->PrintHeader();

    try {
        WDbgArkMemTable::WalkResult result;

        if ( table.Walk(&result) != false ) {
            for ( const auto &address : result ) {
                ExtRemoteTyped object_type("nt!_OBJECT_TYPE", address, false, NULL, NULL);

                if ( !SUCCEEDED(DirectoryObjectTypeCallback(this,
                                                            object_type,
                                                            reinterpret_cast<void*>(display.get()))) ) {
                    err << wa::showminus << __FUNCTION__ << ": DirectoryObjectTypeCallback failed" << endlerr;
                }
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
