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

#include <time.h>

#include "wdbgark.hpp"
#include "ver.hpp"
#include "manipulators.hpp"

namespace wa {

EXT_COMMAND(wa_scan,
            "Scan system (execute all commands)",
            "{log;s,o;log;Log file name}"\
            "{reload;b,o;reload;Force to reload symbols}"\
            /*"{colorize;b,o;colorize;Use default theme}"*/) {
    RequireKernelMode();

    if ( HasArg("reload") ) {
        m_Symbols->Reload("/f /n");
    }

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    if ( HasArg("log") ) {
        Execute(".logopen /t %s", GetArgStr("log"));
    }

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    out << wa::showplus << "WinDBG Anti-RootKit v" << VER_MAJOR << "." << VER_MINOR << endlout;

    const auto time_start = std::time(nullptr);
    
    std::tm buf;
    localtime_s(&buf, &time_start);

    char time_buffer[26] = { 0 };
    if ( !asctime_s(&time_buffer[0], sizeof(time_buffer), &buf) ) {
        time_buffer[24] = '\0';  // remove \n
    }

    out << wa::showplus << "Scan start: " << time_buffer << endlout;

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    Execute("vertarget");
    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    Execute("!vm 7e");
    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;

    for ( const auto& [cmd_name, cmd] : m_scan_commands ) {
        out << wa::showplus << "<b>" << cmd_name << "</b>" << endlout;

        try {
            cmd();   // call the command without parameters
        } catch ( const ExtStatusException &Ex ) {
            err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        }
    }

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    out << wa::showplus << "WinDBG Anti-RootKit v" << std::dec << VER_MAJOR << "." << VER_MINOR << endlout;

    const auto time_end = std::time(nullptr);
    localtime_s(&buf, &time_end);

    if ( !asctime_s(&time_buffer[0], sizeof(time_buffer), &buf) ) {
        time_buffer[24] = '\0';  // remove \n
    }

    out << wa::showplus << "Scan end: " << time_buffer << endlout;

    out << wa::showplus << "Scan took ";
    out << std::fixed << std::setprecision(2) << difftime(time_end, time_start) << " seconds" << endlout;

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;

    if ( HasArg("log") ) {
        Execute(".logclose");
    }
}

}   // namespace wa
