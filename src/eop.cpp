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
#include "processhlp.hpp"
#include "process.hpp"

namespace wa {

EXT_COMMAND(wa_eop, "Checks processes for Elevation of Privilege", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    out << wa::showplus << "Searching for EoP" << endlout;

    auto process_helper = std::make_unique<WDbgArkProcess>(m_sym_cache);

    if ( !process_helper->IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": failed to init process helper" << endlerr;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeProcessToken);
    display->PrintHeader();

    try {
        for ( const auto& process : process_helper->GetProcessList() ) {
            display->Analyze(process);
        }
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
