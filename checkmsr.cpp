/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2014  Vyacheslav Rusakoff
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

EXT_COMMAND(wa_checkmsr, "Output system MSRs (live debug only!)", "") {
    RequireKernelMode();
    RequireLiveKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    std::unique_ptr<WDbgArkAnalyze> display(new WDbgArkAnalyze(WDbgArkAnalyze::AnalyzeTypeDefault));

    if ( !display->SetOwnerModule("nt") )
        warn << __FUNCTION__ ": SetOwnerModule failed" << endlwarn;

    display->PrintHeader();

    try {
        unsigned __int64  msr_address = 0;
        std::stringstream expression;

        ReadMsr(SYSENTER_EIP_MSR, &msr_address);

        expression << std::showbase << std::hex << msr_address;
        display->AnalyzeAddressAsRoutine(g_Ext->EvalExprU64(expression.str().c_str()), "SYSENTER_EIP_MSR", "");
    }
    catch ( const ExtStatusException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}
