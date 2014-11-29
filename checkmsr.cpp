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

EXT_COMMAND(wa_checkmsr,
            "Output system MSRs (live debug only!)",
            "")
{
    RequireKernelMode();
    RequireLiveKernelMode();

    Init();

    WDbgArkAnalyze display;
    stringstream   tmp_stream;
    display.Init( &tmp_stream, AnalyzeTypeDefault );
    display.SetOwnerModule( "nt" );
    display.PrintHeader();

    try
    {
        unsigned __int64 msr_address = 0;
        stringstream     expression;

        ReadMsr( SYSENTER_EIP_MSR, &msr_address );

        expression << std::showbase << std::hex << msr_address;

        display.AnalyzeAddressAsRoutine( g_Ext->EvalExprU64( expression.str().c_str() ), "SYSENTER_EIP_MSR", "" );
    }
    catch ( ExtStatusException Ex )
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