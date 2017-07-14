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

    uint64_t offset = 0;

    if ( !m_sym_cache->GetSymbolOffset("nt!ObTypeIndexTable", true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to find nt!ObTypeIndexTable" << endlerr;
        return;
    }

    out << wa::showplus << "nt!ObTypeIndexTable: " << std::hex << std::showbase << offset << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeObjType);

    if ( !display->AddRangeWhiteList("nt") ) {
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;
    }

    display->SetWhiteListEntries(GetObjectTypesWhiteList());
    display->PrintHeader();

    try {
        walkresType output_list;
        WalkAnyTable(offset, 2 * m_PtrSize, 0x100, m_PtrSize, "", &output_list, true);

        for ( const auto &walk_info : output_list ) {
            ExtRemoteTyped object_type("nt!_OBJECT_TYPE", walk_info.address, false, NULL, NULL);

            if ( !SUCCEEDED(DirectoryObjectTypeCallback(this,
                                                        object_type,
                                                        reinterpret_cast<void*>(display.get()))) ) {
                err << wa::showminus << __FUNCTION__ << ": DirectoryObjectTypeCallback failed" << endlerr;
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
