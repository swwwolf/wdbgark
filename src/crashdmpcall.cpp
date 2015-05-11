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
    Vista+. Look for IopLoadCrashdumpDriver(). It's just a table with pure pointers.
*/

#include <sstream>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {

unsigned __int32 GetCrashdmpCallTableCount();

EXT_COMMAND(wa_crashdmpcall, "Output kernel-mode nt!CrashdmpCallTable", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying nt!CrashdmpCallTable" << endlout;

    if ( m_system_ver->GetStrictVer() <= W2K3_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    unsigned __int32 table_count = GetCrashdmpCallTableCount();

    if ( !table_count ) {
        err << wa::showminus << __FUNCTION__ << ": unknown table count" << endlerr;
        return;
    }

    unsigned __int64 offset = 0;

    if ( !m_sym_cache->GetSymbolOffset("nt!CrashdmpCallTable", true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to find nt!CrashdmpCallTable" << endlerr;
        return;
    }

    out << wa::showplus << "nt!CrashdmpCallTable: " << std::hex << std::showbase << offset << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    if ( !display->AddRangeWhiteList("crashdmp") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    display->PrintHeader();

    try {
        walkresType output_list;

        // skip first two entries, they're system reserved signatures
        unsigned __int32 skip_offset = 2 * sizeof(unsigned __int32);
        WalkAnyTable(offset, skip_offset, table_count, "", &output_list);

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

unsigned __int32 GetCrashdmpCallTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() )
        return 0;

    if ( system_ver.IsBuildInRangeStrict(VISTA_RTM_VER, VISTA_SP1_VER) )
        return 7;
    else if ( system_ver.IsBuildInRangeStrict(VISTA_SP2_VER, W7SP1_VER) )
        return 8;
    else if ( system_ver.GetStrictVer() >= W8RTM_VER )
        return 12;

    return 0;
}

}   // namespace wa
