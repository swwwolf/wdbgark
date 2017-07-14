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

/*
    >= Vista && < Windows 8.1 -> nt!g_CiCallbacks
    >= Windows 8.1            -> nt!SeCiCallbacks

    Look for SepInitializeCodeIntegrity(). It's just a table with pure pointers.
*/

#include <sstream>
#include <memory>
#include <string>
#include <utility>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {

std::pair<uint32_t, uint32_t> GetCiCallbacksTableCount() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return std::make_pair(0, 0);
    }

    if ( system_ver.IsBuildInRangeStrict(VISTA_RTM_VER, W7SP1_VER) ) {
        return std::make_pair(3, 0);
    } else if ( system_ver.GetStrictVer() == W8RTM_VER ) {
        return std::make_pair(7, g_Ext->m_PtrSize);
    } else if ( system_ver.GetStrictVer() == W81RTM_VER ) {
        return std::make_pair(12, g_Ext->m_PtrSize);
    } else if ( system_ver.IsBuildInRangeStrict(W10RTM_VER, W10TH2_VER) ) {
        return std::make_pair(18, g_Ext->m_PtrSize);
    } else if ( system_ver.GetStrictVer() == W10RS1_VER ) {
        return std::make_pair(19, g_Ext->m_PtrSize);
    } else if ( system_ver.GetStrictVer() >= W10RS2_VER ) {
        return std::make_pair(22, g_Ext->m_PtrSize);
    }

    return std::make_pair(0, 0);
}

EXT_COMMAND(wa_cicallbacks, "Output kernel-mode nt!g_CiCallbacks or nt!SeCiCallbacks", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    if ( m_system_ver->GetStrictVer() <= W2K3_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    std::string symbol_name;

    if ( m_system_ver->GetStrictVer() <= W8RTM_VER ) {
        out << wa::showplus << "Displaying nt!g_CiCallbacks" << endlout;
        symbol_name = "nt!g_CiCallbacks";
    } else {
        out << wa::showplus << "Displaying nt!SeCiCallbacks" << endlout;
        symbol_name = "nt!SeCiCallbacks";
    }

    std::pair<uint32_t, uint32_t> table_count_skip_offset = GetCiCallbacksTableCount();

    if ( !table_count_skip_offset.first ) {
        err << wa::showminus << __FUNCTION__ << ": unknown table count" << endlerr;
        return;
    }

    uint64_t offset = 0;

    if ( !m_sym_cache->GetSymbolOffset(symbol_name, true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to find " << symbol_name << endlerr;
        return;
    }

    out << wa::showplus << symbol_name << ": " << std::hex << std::showbase << offset << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    if ( !display->AddRangeWhiteList("ci") ) {
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;
    }

    display->PrintHeader();

    try {
        walkresType output_list;
        WalkAnyTable(offset,
                     table_count_skip_offset.second,
                     table_count_skip_offset.first,
                     m_PtrSize,
                     "",
                     &output_list);

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

}   // namespace wa
