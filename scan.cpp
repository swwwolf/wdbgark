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

#include "wdbgark.hpp"

EXT_COMMAND(wa_scan,
            "Scan system",
            "{log;s;o;log,Log file name}{reload;b;o;reload,Force to reload symbols}")
{
    RequireKernelMode();

    Init();

    if ( HasArg( "reload" ) )
            m_Symbols->Reload( "/f /n" );

    if ( HasArg( "log" ) )
        Execute( ".logopen /t %s", GetArgStr( "log" ) );

    try
    {
        out << "!wa_ssdt" << endlout;
        wa_ssdt();
    }
    catch( ... ) {}
    
    try
    {
        out << "!wa_w32psdt" << endlout;
        wa_w32psdt();
    }
    catch( ... ) {}

    try
    {
        out << "!wa_idt" << endlout;
        wa_idt();
    }
    catch( ... ) {}

    try
    {
        out << "!wa_checkmsr" << endlout;
        wa_checkmsr();
    }
    catch( ... ) {}

    try
    {
        out << "!wa_systemcb" << endlout;
        wa_systemcb();
    }
    catch( ... ) {}

    try
    {
        out << "!wa_objtype" << endlout;
        wa_objtype();
    }
    catch( ... ) {}

    try
    {
        out << "!wa_objtypeidx" << endlout;
        wa_objtypeidx();
    }
    catch( ... ) {}

    try
    {
        out << "!wa_callouts" << endlout;
        wa_callouts();
    }
    catch( ... ) {}

    try
    {
        out << "!wa_pnptable" << endlout;
        wa_pnptable();
    }
    catch( ... ) {}

    if ( HasArg( "log" ) )
        Execute( ".logclose" );
}