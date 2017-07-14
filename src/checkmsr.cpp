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
#include "util.hpp"

namespace wa {

EXT_COMMAND(wa_checkmsr, "Output system MSRs (live debug only!)", "") {
    RequireLiveKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    if ( !display->AddRangeWhiteList("nt") ) {
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;
    }

    display->PrintHeader();

    try {
        if ( !m_is_cur_machine64 ) {
            uint64_t msr_address = 0;
            ReadMsr(IA32_SYSENTER_EIP, &msr_address);

            if ( !NormalizeAddress(msr_address, &msr_address) ) {
                err << wa::showminus << __FUNCTION__ << ": NormalizeAddress failed" << endlerr;
            }

            display->Analyze(msr_address, "IA32_SYSENTER_EIP", "");
        } else {
            uint64_t msr_address_lstar = 0;
            ReadMsr(MSR_LSTAR, &msr_address_lstar);
            
            if ( !NormalizeAddress(msr_address_lstar, &msr_address_lstar) ) {
                err << wa::showminus << __FUNCTION__ << ": NormalizeAddress failed" << endlerr;
            }

            display->Analyze(msr_address_lstar, "MSR_LSTAR", "");

            uint64_t msr_address_cstar = 0;
            ReadMsr(MSR_CSTAR, &msr_address_cstar);
            
            if ( !NormalizeAddress(msr_address_cstar, &msr_address_cstar) ) {
                err << wa::showminus << __FUNCTION__ << ": NormalizeAddress failed" << endlerr;
            }

            display->Analyze(msr_address_cstar, "MSR_CSTAR", "");
        }
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
