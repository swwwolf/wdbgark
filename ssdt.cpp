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
#include "sdt_w32p.hpp"

EXT_COMMAND(wa_ssdt,
            "Output the System Service Descriptor Table",
            "")
{
    RequireKernelMode();
    Init();

    out << "Displaying nt!KiServiceTable" << endlout;

    unsigned __int64 offset = 0;
    unsigned long    limit  = 0;

    try
    {
        if ( !GetSymbolOffset( "nt!KiServiceLimit", true, &offset ) )
        {
            err << __FUNCTION__ << ": failed to find nt!KiServiceLimit" << endlerr;
            return;
        }

        out << "[+] nt!KiServiceLimit: " << std::hex << std::showbase << offset << endlout;

        ExtRemoteData ki_service_limit( offset, sizeof( limit ) );
        limit = ki_service_limit.GetUlong();

        if ( !limit )
        {
            err << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << "[+] ServiceLimit:      " << std::hex << std::showbase << limit << endlout;

        if ( !GetSymbolOffset( "nt!KiServiceTable", true, &offset ) )
        {
            err << __FUNCTION__ << ": failed to find nt!KiServiceTable" << endlerr;
            return;
        }

        out << "[+] nt!KiServiceTable: " << std::hex << std::showbase << offset << endlout;
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return;
    }
    catch( ExtInterruptException Ex )
    {
        throw Ex;
    }

    WDbgArkAnalyze display;
    stringstream   tmp_stream;
    display.Init( &tmp_stream, AnalyzeTypeDefault );
    display.SetOwnerModule( "nt" );
    display.PrintHeader();

    try
    {
        for ( unsigned long i = 0; i < limit; i++ )
        {
            if ( m_is_cur_machine64 )
            {
                string routine_name = get_service_table_routine_name( KiServiceTable_x64, i );

                ExtRemoteData service_offset_full( offset + i * sizeof( long ), sizeof( long ) );
                long service_offset = service_offset_full.GetLong();

                if ( m_minor_build >= VISTA_RTM_VER )
                    service_offset >>= 4;
                else
                    service_offset &= ~MAX_FAST_REFS_X64;

                display.AnalyzeAddressAsRoutine( offset + service_offset, routine_name, "" );
                display.PrintFooter();
            }
            else
            {
                string routine_name = get_service_table_routine_name( KiServiceTable_x86, i );

                ExtRemoteData service_address( offset + i * m_PtrSize, m_PtrSize );
                display.AnalyzeAddressAsRoutine( service_address.GetPtr(), routine_name, "" );
                display.PrintFooter();
            }
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( ExtInterruptException Ex )
    {
        throw Ex;
    }

    display.PrintFooter();
}

EXT_COMMAND(wa_w32psdt,
            "Output the Win32k Service Descriptor Table",
            "{process;e64;o;process,Any GUI EPROCESS address (use explorer.exe)}")
{
    RequireKernelMode();
    Init();

    out << "Displaying win32k!W32pServiceTable" << endlout;

    WDbgArkProcess process;
    process.Init();

    unsigned __int64 set_eprocess = 0;

    if ( HasArg( "process" ) )
        set_eprocess = GetArgU64( "process" );
    else
        set_eprocess = process.FindEProcessAnyGUIProcess();

    if ( !SUCCEEDED( process.SetImplicitProcess( set_eprocess ) ) )
        return;

    unsigned __int64 offset = 0;
    unsigned long    limit  = 0;

    try
    {
        if ( !GetSymbolOffset( "win32k!W32pServiceLimit", true, &offset ) )
        {
            err << __FUNCTION__ << ": failed to find win32k!W32pServiceLimit" << endlerr;
            return;
        }

        out << "[+] win32k!W32pServiceLimit: " << std::hex << std::showbase << offset << endlout;

        ExtRemoteData w32_service_limit( offset, sizeof( limit ) );
        limit = w32_service_limit.GetUlong();

        if ( !limit )
        {
            err << __FUNCTION__ << ": invalid service limit number" << endlerr;
            return;
        }

        out << "[+] ServiceLimit:            " << std::hex << std::showbase << limit << endlout;

        if ( !GetSymbolOffset( "win32k!W32pServiceTable", true, &offset ) )
        {
            err << __FUNCTION__ << ": failed to find win32k!W32pServiceTable" << endlerr;
            return;
        }

        out << "[+] win32k!W32pServiceTable: " << std::hex << std::showbase << offset << endlout;
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return;
    }
    catch( ExtInterruptException Ex )
    {
        throw Ex;
    }

    WDbgArkAnalyze display;
    stringstream   tmp_stream;
    display.Init( &tmp_stream, AnalyzeTypeDefault );
    display.SetOwnerModule( "win32k" );
    display.PrintHeader();

    try
    {
        for ( unsigned long i = 0; i < limit; i++ )
        {
            if ( m_is_cur_machine64 )
            {
                string routine_name = get_service_table_routine_name( W32pServiceTable_x64, i );

                ExtRemoteData service_offset_full( offset + i * sizeof( long ), sizeof( long ) );
                long service_offset = service_offset_full.GetLong();

                if ( m_minor_build >= VISTA_RTM_VER )
                    service_offset >>= 4;
                else
                    service_offset &= ~MAX_FAST_REFS_X64;

                display.AnalyzeAddressAsRoutine( offset + service_offset, routine_name, "" );
                display.PrintFooter();
            }
            else
            {
                string routine_name = get_service_table_routine_name( W32pServiceTable_x86, i );

                ExtRemoteData service_address( offset + i * m_PtrSize, m_PtrSize );
                display.AnalyzeAddressAsRoutine( service_address.GetPtr(), routine_name, "" );
                display.PrintFooter();
            }
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( ExtInterruptException Ex )
    {
        throw Ex;
    }

    display.PrintFooter();
}