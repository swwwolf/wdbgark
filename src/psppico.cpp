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

void WDbgArk::WalkPicoTable(const std::string &table_name) {
    out << wa::showplus << "Displaying " << table_name << endlout;

    if ( m_system_ver->GetStrictVer() <= W81RTM_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    WDbgArkMemTable table(m_sym_cache, table_name);

    if ( table.IsValid() ) {
        table.SetTableSkipStart(m_PtrSize);
        table.SetRoutineDelta(m_PtrSize);
    } else {
        err << wa::showminus << __FUNCTION__ << ": failed to find " << table_name << endlerr;
        return;
    }

    out << wa::showplus << table_name << ": " << std::hex << std::showbase << table.GetTableStart() << endlout;

    uint32_t count = static_cast<uint32_t>(ExtRemoteData(table.GetTableStart(), m_PtrSize).GetPtr() / m_PtrSize);

    if ( !count ) {
        out << wa::showplus << __FUNCTION__ << ": empty table" << endlout;
        return;
    } else {
        count--;
    }

    table.SetTableCount(count);

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

EXT_COMMAND(wa_psppico, "Output kernel-mode Pico tables", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    WalkPicoTable("nt!PspPicoProviderRoutines");

    if ( SUCCEEDED(m_Symbols3->GetModuleByModuleName2("lxcore", 0UL, 0UL, nullptr, nullptr)) ) {
        WalkPicoTable("lxcore!LxpRoutines");
    }
}

}   // namespace wa
