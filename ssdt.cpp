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

#include "wdbgark.h"
#include "sdt_w32p.h"

EXT_COMMAND(
    ssdt,
    "Output the System Service Descriptor Table\n",
    ""
    )
{
    RequireKernelMode();

    Init();

    out << "******" << endlout;
    out << "*    ";
    out << std::left << std::setw( 16 ) << "Address" << std::right << std::setw( 6 ) << ' ';
    out << std::left << std::setw( 40 ) << "Routine name" << std::right << std::setw( 12 ) << ' ';
    out << std::left << std::setw( 70 ) << "Symbol" << std::right << std::setw( 4 ) << ' ';
    out << std::left << std::setw( 30 ) << "Module" << std::right << std::setw( 1 ) << ' ';
    out << "*" << endlout;
    out << "******" << endlout;

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
                    if ( is_cur_machine64 )
                    {
                        string routine_name = get_service_table_routine_name( KiServiceTable_x64, i );

                        ExtRemoteData service_offset_full( offset + i * sizeof( long ), sizeof( long ) );
                        long service_offset = service_offset_full.GetLong();

                        if ( minor_build >= VISTA_RTM_VER )
                            service_offset >>= 4;
                        else
                            service_offset &= 0xFFFFFFF0;

                        AnalyzeAddressAsRoutine( offset + service_offset, routine_name, "" );
                    }
                    else
                    {
                        string routine_name = get_service_table_routine_name( KiServiceTable_x86, i );

                        ExtRemoteData service_address( offset + i * m_PtrSize, m_PtrSize );
                        AnalyzeAddressAsRoutine( service_address.GetPtr(), routine_name, "" );
                    }
                }
            }
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << endlerr;
    }

    out << "******" << endlout;
}

EXT_COMMAND(
    w32psdt,
    "Output the Win32k Service Descriptor Table\n",
    ""
    )
{
    RequireKernelMode();

    Init();

    out << "******" << endlout;
    out << "*    ";
    out << std::left << std::setw( 16 ) << "Address" << std::right << std::setw( 6 ) << ' ';
    out << std::left << std::setw( 40 ) << "Routine name" << std::right << std::setw( 12 ) << ' ';
    out << std::left << std::setw( 70 ) << "Symbol" << std::right << std::setw( 4 ) << ' ';
    out << std::left << std::setw( 30 ) << "Module" << std::right << std::setw( 1 ) << ' ';
    out << "*" << endlout;
    out << "******" << endlout;

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
                    if ( is_cur_machine64 )
                    {
                        string routine_name = get_service_table_routine_name( W32pServiceTable_x64, i );

                        ExtRemoteData service_offset_full( offset + i * sizeof( long ), sizeof( long ) );
                        long service_offset = service_offset_full.GetLong();

                        if ( minor_build >= VISTA_RTM_VER )
                            service_offset >>= 4;
                        else
                            service_offset &= 0xFFFFFFF0;

                        AnalyzeAddressAsRoutine( offset + service_offset, routine_name, "" );
                    }
                    else
                    {
                        string routine_name = get_service_table_routine_name( W32pServiceTable_x86, i );

                        ExtRemoteData service_address( offset + i * m_PtrSize, m_PtrSize );
                        AnalyzeAddressAsRoutine( service_address.GetPtr(), routine_name, "" );
                    }
                }
            }
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << endlerr;
    }

    out << "******" << endlout;
}