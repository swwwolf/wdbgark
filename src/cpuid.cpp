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

#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "util.hpp"

namespace wa {

EXT_COMMAND(wdrce_cpuid,
            "Execute CPUID instruction (live debug only!)",
            "{eax;ed32,r;eax;EAX register (function_id)}{ecx;ed32,o,d=0x0;ecx;ECX register (subfunction_id)}") {
    RequireLiveKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    if ( !m_wdrce->Init() ) {
        err << wa::showminus << __FUNCTION__ ": WDbgArkRce init failed" << endlerr;
        return;
    }

    try {
        const int function_id = static_cast<int>(GetArgU64("eax"));
        const int subfunction_id = static_cast<int>(GetArgU64("ecx"), false);

        const auto result = m_wdrce->ExecuteCpuid(function_id, subfunction_id);

        if ( !result ) {
            err << wa::showminus << __FUNCTION__ ": ExecuteCpuid failed" << endlerr;
            return;
        }

        out << wa::showplus << "Hit \'go\' to continue execution" << endlout;
        WaitForGoInput();
        Execute("g;");
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch ( const ExtInvalidArgumentException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }
}

}   // namespace wa
