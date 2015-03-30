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

#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {

EXT_COMMAND(wa_checkmsr, "Output system MSRs (live debug only!)", "") {
    RequireLiveKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    auto display = WDbgArkAnalyzeBase::Create();

    if ( !display->AddRangeWhiteList("nt") )
        warn << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    display->PrintHeader();

    try {
        if ( !m_is_cur_machine64 ) {
            unsigned __int64  msr_address = 0;
            std::stringstream expression;

            ReadMsr(IA32_SYSENTER_EIP, &msr_address);
            expression << std::showbase << std::hex << msr_address;
            display->Analyze(g_Ext->EvalExprU64(expression.str().c_str()), "IA32_SYSENTER_EIP", "");
        } else {
            unsigned __int64  msr_address_lstar = 0;
            unsigned __int64  msr_address_cstar = 0;
            std::stringstream expression_lstar;
            std::stringstream expression_cstar;

            ReadMsr(MSR_LSTAR, &msr_address_lstar);
            expression_lstar << std::showbase << std::hex << msr_address_lstar;
            display->Analyze(g_Ext->EvalExprU64(expression_lstar.str().c_str()), "MSR_LSTAR", "");

            ReadMsr(MSR_CSTAR, &msr_address_cstar);
            expression_cstar << std::showbase << std::hex << msr_address_cstar;
            display->Analyze(g_Ext->EvalExprU64(expression_cstar.str().c_str()), "MSR_CSTAR", "");
        }
    }
    catch ( const ExtStatusException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
