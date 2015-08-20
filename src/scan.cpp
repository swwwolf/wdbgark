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

#include <ctime>

#include "wdbgark.hpp"
#include "ver.hpp"
#include "manipulators.hpp"

namespace wa {

EXT_COMMAND(wa_scan,
            "Scan system (execute all commands)",
            "{log;s;o;log,Log file name}"\
            "{reload;b;o;reload,Force to reload symbols}"\
            /*"{colorize;b;o;colorize,Use default theme}"*/) {
    RequireKernelMode();

    if ( HasArg("reload") )
        m_Symbols->Reload("/f /n");

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( HasArg("log") )
        Execute(".logopen /t %s", GetArgStr("log"));

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    out << wa::showplus << "WinDBG Anti-RootKit v" << VER_MAJOR << "." << VER_MINOR << endlout;

    char time_buffer[26];
    std::time_t time_start = std::time(nullptr);

    out << wa::showplus << "Scan start: ";

    if ( !ctime_s(time_buffer, sizeof(time_buffer), &time_start) ) {
        time_buffer[24] = '\0';  // remove \n
        out << time_buffer;
    }

    out << endlout;

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    Execute("vertarget");
    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    Execute("!vm");
    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;

    try {
        out << wa::showplus << "<b>!wa_ssdt</b>" << endlout;
        wa_ssdt();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_w32psdt</b>" << endlout;
        wa_w32psdt();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_idt</b>" << endlout;
        wa_idt();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_gdt</b>" << endlout;
        wa_gdt();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_checkmsr</b>" << endlout;
        wa_checkmsr();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_systemcb</b>" << endlout;
        wa_systemcb();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_objtype</b>" << endlout;
        wa_objtype();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_objtypeidx</b>" << endlout;
        wa_objtypeidx();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_objtypecb</b>" << endlout;
        wa_objtypecb();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_callouts</b>" << endlout;
        wa_callouts();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_pnptable</b>" << endlout;
        wa_pnptable();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_crashdmpcall</b>" << endlout;
        wa_crashdmpcall();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_haltables</b>" << endlout;
        wa_haltables();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_ciinfo</b>" << endlout;
        wa_ciinfo();
    } catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_cicallbacks</b>" << endlout;
        wa_cicallbacks();
    } catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    try {
        out << wa::showplus << "<b>!wa_drvmajor</b>" << endlout;
        wa_drvmajor();
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;
    out << wa::showplus << "WinDBG Anti-RootKit v" << std::dec << VER_MAJOR << "." << VER_MINOR << endlout;

    std::time_t time_end = std::time(nullptr);
    out << wa::showplus << "Scan end: ";

    if ( !ctime_s(time_buffer, sizeof(time_buffer), &time_end) ) {
        time_buffer[24] = '\0';  // remove \n
        out << time_buffer;
    }

    out << endlout;

    out << wa::showplus << "Scan took ";
    out << std::fixed << std::setprecision(2) << difftime(time_end, time_start) << " seconds" << endlout;

    out << wa::showplus << "--------------------------------------------------------------------------" << endlout;

    if ( HasArg("log") )
        Execute(".logclose");
}

}   // namespace wa
