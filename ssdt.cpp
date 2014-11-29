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

    WDbgArkAnalyze display;
    stringstream   tmp_stream;
    display.Init( &tmp_stream, AnalyzeTypeDefault );
    display.SetOwnerModule( "nt" );
    display.PrintHeader();

    try
    {
        unsigned __int64 offset = 0;

        if ( GetSymbolOffset( "nt!KiServiceLimit", true, &offset ) )
        {
            ExtRemoteData ki_service_limit( offset, sizeof( unsigned long ) );

            if ( !ki_service_limit.GetUlong() )
            {
                err << "Invalid service limit number" << endlerr;
                return;
            }

            if ( GetSymbolOffset( "nt!KiServiceTable", true, &offset ) )
            {
                for ( unsigned long i = 0; i < ki_service_limit.GetUlong(); i++ )
                {
                    if ( m_is_cur_machine64 )
                    {
                        string routine_name = get_service_table_routine_name( KiServiceTable_x64, i );

                        ExtRemoteData service_offset_full( offset + i * sizeof( long ), sizeof( long ) );
                        long service_offset = service_offset_full.GetLong();

                        if ( m_minor_build >= VISTA_RTM_VER )
                            service_offset >>= 4;
                        else
                            service_offset &= 0xFFFFFFF0;

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
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << endlerr;
    }
    */

    display.PrintFooter();
}

EXT_COMMAND(wa_w32psdt,
            "Output the Win32k Service Descriptor Table",
            "{process;e64;o;process,Any GUI EPROCESS address (use explorer.exe)}")
{
    RequireKernelMode();
    Init();

    out << "Displaying win32k!W32pServiceTable" << endlout;

    unsigned __int64 set_eprocess     = 0;
    unsigned __int64 current_eprocess = 0;

    if ( HasArg( "process" ) )
        set_eprocess = GetArgU64( "process" );

    if ( !set_eprocess )
    {
        WDbgArkProcess process;

        process.Init();
        set_eprocess = process.FindEProcessAnyGUIProcess();

        if ( !set_eprocess )
        {
            err << "Failed to find GUI process" << endlerr;
            return;
        }
    }

    if ( !SUCCEEDED( g_Ext->m_System2->GetImplicitProcessDataOffset( &current_eprocess ) ) )
    {
        err << "Failed to get current EPROCESS" << endlerr;
        return;
    }

    if ( current_eprocess != set_eprocess )
    {
        if ( !SUCCEEDED( g_Ext->m_System2->SetImplicitProcessDataOffset( set_eprocess ) ) )
        {
            err << "Failed to set implicit process to " << std::hex << std::showbase << set_eprocess << endlerr;
            return;
        }
    }

    WDbgArkAnalyze display;
    stringstream   tmp_stream;
    display.Init( &tmp_stream, AnalyzeTypeDefault );
    display.SetOwnerModule( "win32k" );
    display.PrintHeader();

    try
    {
        unsigned __int64 offset = 0;

        if ( GetSymbolOffset( "win32k!W32pServiceLimit", true, &offset ) )
        {
            ExtRemoteData w32_service_limit( offset, sizeof( unsigned long ) );

            if ( !w32_service_limit.GetUlong() )
            {
                err << "Invalid service limit number" << endlerr;
                return;
            }

            if ( GetSymbolOffset( "win32k!W32pServiceTable", true, &offset ) )
            {
                for ( unsigned long i = 0; i < w32_service_limit.GetUlong(); i++ )
                {
                    if ( m_is_cur_machine64 )
                    {
                        string routine_name = get_service_table_routine_name( W32pServiceTable_x64, i );

                        ExtRemoteData service_offset_full( offset + i * sizeof( long ), sizeof( long ) );
                        long service_offset = service_offset_full.GetLong();

                        if ( m_minor_build >= VISTA_RTM_VER )
                            service_offset >>= 4;
                        else
                            service_offset &= 0xFFFFFFF0;

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
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << endlerr;
    }
    */

    display.PrintFooter();

    if ( current_eprocess != set_eprocess )
    {
        if ( !SUCCEEDED( g_Ext->m_System2->SetImplicitProcessDataOffset( current_eprocess ) ) )
            err << "Failed to revert implicit process to " << std::hex << std::showbase << current_eprocess << endlerr;
    }
}