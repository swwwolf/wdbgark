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
#include "process.hpp"

namespace wa {

EXT_COMMAND(wa_chknirvana, "Checks processes for Hooking Nirvana instrumentation", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Searching for Hooking Nirvana instrumentation" << endlout;

    if ( m_is_cur_machine64 && m_system_ver->GetStrictVer() <= W2K3_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    if ( !m_is_cur_machine64 && m_system_ver->GetStrictVer() <= W81RTM_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    auto process_helper = std::make_unique<WDbgArkProcess>(m_dummy_pdb);

    if ( !process_helper->IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": failed to init process helper" << endlerr;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeCallback);
    display->PrintHeader();

    try {
        for ( const auto &process : process_helper->GetProcessList() ) {
            auto address = process_helper->GetInstrumentationCallback(process);

            if ( address ) {
                HRESULT result = process_helper->SetImplicitProcess(process.eprocess);

                if ( FAILED(result) )
                    continue;

                // reload user-mode symbols without output
                // I'm cheating here executing .cache command
                ExtCaptureOutputA ignore_output;
                ignore_output.Start();
                Execute(".cache forcedecodeuser");
                m_Symbols->Reload("/user");
                ignore_output.Stop();

                std::stringstream info;
                info << std::setw(45);
                info << "<exec cmd=\"dx -r1 *(nt!_EPROCESS *)" << std::hex << std::showbase;
                info << process.eprocess << "\">dx" << "</exec>" << " ";

                info << "<exec cmd=\".process /r /p " << std::hex << std::showbase << process.eprocess << " ";
                info << "\">.process" << "</exec>" << " ";

                info << "<exec cmd=\"u " << std::hex << std::showbase << address << " L50";
                info << "\">u50" << "</exec>";
                info << "</exec>";

                display->Analyze(address, "Nirvana", info.str());

                process_helper->RevertImplicitProcess();
                display->PrintFooter();
            }
        }
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
