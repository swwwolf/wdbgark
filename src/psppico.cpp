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

#include <sstream>
#include <memory>
#include <string>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {

void WDbgArk::WalkPicoTable(const std::string &table_name) {
    out << wa::showplus << "Displaying " << table_name << endlout;

    if ( m_system_ver->GetStrictVer() <= W81RTM_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    uint64_t offset = 0;

    if ( !m_sym_cache->GetSymbolOffset(table_name, true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to find " << table_name << endlerr;
        return;
    }

    out << wa::showplus << table_name << ": " << std::hex << std::showbase << offset << endlout;

    uint32_t count = static_cast<uint32_t>(ExtRemoteData(offset, m_PtrSize).GetPtr() / m_PtrSize);

    if ( !count ) {
        out << wa::showplus << __FUNCTION__ << ": empty table" << endlout;
        return;
    }

    count--;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);
    display->PrintHeader();

    try {
        walkresType output_list;
        WalkAnyTable(offset, m_PtrSize, count, "", &output_list);

        for ( const auto &walk_info : output_list ) {
            display->Analyze(walk_info.address, walk_info.type, walk_info.info);
            display->PrintFooter();
        }
    } catch ( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

EXT_COMMAND(wa_psppico, "Output kernel-mode Pico tables", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    WalkPicoTable("nt!PspPicoProviderRoutines");
    WalkPicoTable("lxcore!LxpRoutines");
}

}   // namespace wa
