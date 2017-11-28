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

#include <sstream>
#include <memory>
#include <string>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"
#include "memtable.hpp"

namespace wa {

uint32_t GetPspPicoTableCount();
uint32_t GetLxpRoutinesTableCount();

EXT_COMMAND(wa_psppico, "Output kernel-mode Pico tables", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    WalkPicoTable("nt!PspPicoProviderRoutines", GetPspPicoTableCount());

    if ( SUCCEEDED(m_Symbols3->GetModuleByModuleName2("lxcore", 0UL, 0UL, nullptr, nullptr)) ) {
        WalkPicoTable("lxcore!LxpRoutines", GetLxpRoutinesTableCount());
    }
}

void WDbgArk::WalkPicoTable(const std::string &table_name, const uint32_t table_count) {
    out << wa::showplus << "Displaying " << table_name << endlout;

    if ( m_system_ver->GetStrictVer() <= W81RTM_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    if ( !table_count ) {
        out << wa::showplus << __FUNCTION__ << ": invalid table count" << endlout;
        return;
    }

    WDbgArkMemTable table(m_sym_cache, table_name);

    if ( table.IsValid() ) {
        table.SetTableSkipStart(m_PtrSize);
        table.SetTableCount(table_count);
        table.SetRoutineDelta(m_PtrSize);
        table.SetCollectNull(true);
    } else {
        err << wa::showminus << __FUNCTION__ << ": failed to find " << table_name << endlerr;
        return;
    }

    out << wa::showplus << table_name << ": " << std::hex << std::showbase << table.GetTableStart() << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);
    display->PrintHeader();

    try {
        WDbgArkMemTable::WalkResult result;

        if ( table.Walk(&result) != false ) {
            for ( const auto &address : result ) {
                display->Analyze(address, "", "");
                display->PrintFooter();
            }
        }
    } catch ( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

// nt!PspPicoProviderRoutines
uint32_t GetPspPicoTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.GetStrictVer() <= W81RTM_VER ) {
        return 0;
    }

    return 8;
}

// lxcore!LxpRoutines
uint32_t GetLxpRoutinesTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return 0;
    }

    if ( system_ver.GetStrictVer() <= W81RTM_VER ) {
        return 0;
    }

    return 11;
}

}   // namespace wa
