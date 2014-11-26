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

EXT_COMMAND(scan,
            "Run all commands\n",
            "{log;s;o;log,Log file name}")
{
    RequireKernelMode();

    Init();

    if ( HasArg( "log" ) )
        Execute( ".logopen /t %s", GetArgStr( "log" ) );

    try
    {
        out << "!ssdt" << endlout;
        ssdt();
    }
    catch( ... ) {}
    
    try
    {
        out << "!w32psdt" << endlout;
        w32psdt();
    }
    catch( ... ) {}

    try
    {
        out << "!checkmsr" << endlout;
        checkmsr();
    }
    catch( ... ) {}

    try
    {
        out << "!systemcb" << endlout;
        systemcb();
    }
    catch( ... ) {}

    try
    {
        out << "!objtype" << endlout;
        objtype();
    }
    catch( ... ) {}

    try
    {
        out << "!objtypeidx" << endlout;
        objtypeidx();
    }
    catch( ... ) {}

    try
    {
        out << "!callouts" << endlout;
        callouts();
    }
    catch( ... ) {}

    try
    {
        out << "!pnptable" << endlout;
        pnptable();
    }
    catch( ... ) {}

    if ( HasArg( "log" ) )
        Execute( ".logclose" );
}