/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2018  Vyacheslav Rusakoff
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
#include "memtable.hpp"

namespace wa {

uint32_t GetCrashdmpCallTableCount();

EXT_COMMAND(wa_crashdmpcall, "Output kernel-mode nt!CrashdmpCallTable", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    out << wa::showplus << "Displaying nt!CrashdmpCallTable" << endlout;

    if ( m_system_ver->GetStrictVer() <= W2K3_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    const uint32_t table_count = GetCrashdmpCallTableCount();

    if ( !table_count ) {
        err << wa::showminus << __FUNCTION__ << ": unknown table count" << endlerr;
        return;
    }

    WDbgArkMemTable table(m_sym_cache, "nt!CrashdmpCallTable");

    if ( table.IsValid() ) {
        table.SetTableSkipStart(2 * sizeof(uint32_t));  // skip first two entries, they're system reserved signatures
        table.SetTableCount(table_count);
        table.SetRoutineDelta(m_PtrSize);
    } else {
        err << wa::showminus << __FUNCTION__ << ": failed to find nt!CrashdmpCallTable" << endlerr;
        return;
    }

    out << wa::showplus << "nt!CrashdmpCallTable: " << std::hex << std::showbase << table.GetTableStart() << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    if ( !display->AddRangeWhiteList("crashdmp") ) {
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;
    }

    display->PrintHeader();

    try {
        WDbgArkMemTable::WalkResult result;

        if ( table.Walk(&result) != false ) {
            for ( const auto& address : result ) {
                display->Analyze(address, "", "");
                display->PrintFooter();
            }
        } else {
            err << wa::showminus << __FUNCTION__ << ": failed to walk table" << endlerr;
        }
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

uint32_t GetCrashdmpCallTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.IsBuildInRangeStrict(VISTA_RTM_VER, VISTA_SP1_VER) ) {
        return 7;
    } else if ( system_ver.IsBuildInRangeStrict(VISTA_SP2_VER, W7SP1_VER) ) {
        return 8;
    } else if ( system_ver.IsBuildInRangeStrict(W8RTM_VER, W10RS1_VER) ) {
        return 12;
    } else if ( system_ver.GetStrictVer() >= W10RS2_VER ) {
        return 13;
    }

    return 0;
}

}   // namespace wa
