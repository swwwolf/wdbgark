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

/*
    Windows 8.1+. Look for SepInitializeCodeIntegrity(). It's just a table with pure pointers.
*/

#include <sstream>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {

unsigned __int32 GetSeCiCallbacksTableCount();

EXT_COMMAND(wa_secicb, "Output kernel-mode nt!SeCiCallbacks", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying nt!SeCiCallbacks" << endlout;

    if ( m_system_ver->GetStrictVer() <= W8RTM_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    unsigned __int32 table_count = GetSeCiCallbacksTableCount();

    if ( !table_count ) {
        err << wa::showminus << __FUNCTION__ << ": unknown table count" << endlerr;
        return;
    }

    unsigned __int64 offset = 0;

    if ( !m_sym_cache->GetSymbolOffset("nt!SeCiCallbacks", true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to find nt!SeCiCallbacks" << endlerr;
        return;
    }

    out << wa::showplus << "nt!SeCiCallbacks: " << std::hex << std::showbase << offset << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    if ( !display->AddRangeWhiteList("ci") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    display->PrintHeader();

    try {
        walkresType output_list;
        WalkAnyTable(offset, m_PtrSize, table_count, "", &output_list);

        for ( const auto &walk_info : output_list ) {
            display->Analyze(walk_info.address, walk_info.type, walk_info.info);
            display->PrintFooter();
        }
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

unsigned __int32 GetSeCiCallbacksTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() )
        return 0;

    if ( system_ver.GetStrictVer() == W81RTM_VER )
        return 12;
    else if ( system_ver.GetStrictVer() >= W10RTM_VER )
        return 18;

    return 0;
}

}   // namespace wa
