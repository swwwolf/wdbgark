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

/*

Look for NtPlugPlayControl and nt!PlugPlayHandlerTable.

http://processhacker.sourceforge.net/doc/ntpnpapi_8h.html

Table looks like this:

{
    _PLUGPLAY_CONTROL_CLASS PnpControlClass; // 0x0
    ULONG                   Length;          // 0x4
    ULONG_PTR               Routine;         // 0x8
}

XP SP3:

_PlugPlayHandlerTable:
PAGEDATA:005C4438 00 00 00 00                   dd 0
PAGEDATA:005C443C 0C 00 00 00                   dd 0Ch
PAGEDATA:005C4440 9F BF 58 00                   dd offset _PiControlEnumerateDevice@16 ; PiControlEnumerateDevice(x,x,x,x)
PAGEDATA:005C4444 01 00 00 00                   dd 1
PAGEDATA:005C4448 0C 00 00 00                   dd 0Ch
PAGEDATA:005C444C 3F BF 58 00                   dd offset _PiControlRegisterNewDevice@16 ; PiControlRegisterNewDevice(x,x,x,x)
PAGEDATA:005C4450 02 00 00 00                   dd 2
PAGEDATA:005C4454 0C 00 00 00                   dd 0Ch
PAGEDATA:005C4458 8F BE 58 00                   dd offset _PiControlDeregisterDevice@16 ; PiControlDeregisterDevice(x,x,x,x)
PAGEDATA:005C445C 03 00 00 00                   dd 3
PAGEDATA:005C4460 0C 00 00 00                   dd 0Ch
PAGEDATA:005C4464 B5 CD 58 00                   dd offset _PiControlInitializeDevice@16 ; PiControlInitializeDevice(x,x,x,x)
PAGEDATA:005C4468 04 00 00 00                   dd 4
PAGEDATA:005C446C 0C 00 00 00                   dd 0Ch
PAGEDATA:005C4470 CA BD 58 00                   dd offset _PiControlStartDevice@16 ; PiControlStartDevice(x,x,x,x)
PAGEDATA:005C4474 05 00 00 00                   dd 5
PAGEDATA:005C4478 0C 00 00 00                   dd 0Ch
PAGEDATA:005C447C 00 00 00 00                   dd 0
PAGEDATA:005C4480 06 00 00 00                   dd 6
PAGEDATA:005C4484 18 00 00 00                   dd 18h
PAGEDATA:005C4488 14 C0 58 00                   dd offset _PiControlQueryAndRemoveDevice@16 ; PiControlQueryAndRemoveDevice(x,x,x,x)
PAGEDATA:005C448C 07 00 00 00                   dd 7
PAGEDATA:005C4490 10 00 00 00                   dd 10h
PAGEDATA:005C4494 2E 44 4C 00                   dd offset _PiControlUserResponse@16 ; PiControlUserResponse(x,x,x,x)
PAGEDATA:005C4498 08 00 00 00                   dd 8
PAGEDATA:005C449C 10 00 00 00                   dd 10h
PAGEDATA:005C44A0 13 CE 58 00                   dd offset _PiControlGenerateLegacyDevice@16 ; PiControlGenerateLegacyDevice(x,x,x,x)
PAGEDATA:005C44A4 09 00 00 00                   dd 9
PAGEDATA:005C44A8 18 00 00 00                   dd 18h
PAGEDATA:005C44AC ED FD 4B 00                   dd offset _PiControlGetInterfaceDeviceList@16 ; PiControlGetInterfaceDeviceList(x,x,x,x)
PAGEDATA:005C44B0 0A 00 00 00                   dd 0Ah
PAGEDATA:005C44B4 14 00 00 00                   dd 14h
PAGEDATA:005C44B8 B9 A4 4F 00                   dd offset _PiControlGetPropertyData@16 ; PiControlGetPropertyData(x,x,x,x)
PAGEDATA:005C44BC 0B 00 00 00                   dd 0Bh
PAGEDATA:005C44C0 20 00 00 00                   dd 20h
PAGEDATA:005C44C4 FF C0 58 00                   dd offset _PiControlDeviceClassAssociation@16 ; PiControlDeviceClassAssociation(x,x,x,x)
PAGEDATA:005C44C8 0C 00 00 00                   dd 0Ch
PAGEDATA:005C44CC 14 00 00 00                   dd 14h
PAGEDATA:005C44D0 95 C2 4F 00                   dd offset _PiControlGetRelatedDevice@16 ; PiControlGetRelatedDevice(x,x,x,x)
PAGEDATA:005C44D4 0D 00 00 00                   dd 0Dh
PAGEDATA:005C44D8 14 00 00 00                   dd 14h
PAGEDATA:005C44DC 1B BC 4F 00                   dd offset _PiControlGetInterfaceDeviceAlias@16 ; PiControlGetInterfaceDeviceAlias(x,x,x,x)
PAGEDATA:005C44E0 0E 00 00 00                   dd 0Eh
PAGEDATA:005C44E4 14 00 00 00                   dd 14h
PAGEDATA:005C44E8 77 3D 4C 00                   dd offset _PiControlGetSetDeviceStatus@16 ; PiControlGetSetDeviceStatus(x,x,x,x)
PAGEDATA:005C44EC 0F 00 00 00                   dd 0Fh
PAGEDATA:005C44F0 0C 00 00 00                   dd 0Ch
PAGEDATA:005C44F4 C3 C2 58 00                   dd offset _PiControlGetDeviceDepth@16 ; PiControlGetDeviceDepth(x,x,x,x)
PAGEDATA:005C44F8 10 00 00 00                   dd 10h
PAGEDATA:005C44FC 14 00 00 00                   dd 14h
PAGEDATA:005C4500 E1 CE 58 00                   dd offset _PiControlQueryDeviceRelations@16 ; PiControlQueryDeviceRelations(x,x,x,x)
PAGEDATA:005C4504 11 00 00 00                   dd 11h
PAGEDATA:005C4508 10 00 00 00                   dd 10h
PAGEDATA:005C450C AB FF 4F 00                   dd offset _PiControlQueryTargetDeviceRelation@16 ; PiControlQueryTargetDeviceRelation(x,x,x,x)
PAGEDATA:005C4510 12 00 00 00                   dd 12h
PAGEDATA:005C4514 20 00 00 00                   dd 20h
PAGEDATA:005C4518 61 C3 58 00                   dd offset _PiControlQueryConflictList@16 ; PiControlQueryConflictList(x,x,x,x)
PAGEDATA:005C451C 13 00 00 00                   dd 13h
PAGEDATA:005C4520 08 00 00 00                   dd 8
PAGEDATA:005C4524 BB C4 58 00                   dd offset _PiControlRetrieveDockData@16 ; PiControlRetrieveDockData(x,x,x,x)
PAGEDATA:005C4528 14 00 00 00                   dd 14h
PAGEDATA:005C452C 0C 00 00 00                   dd 0Ch
PAGEDATA:005C4530 2B BE 58 00                   dd offset _PiControlResetDevice@16 ; PiControlResetDevice(x,x,x,x)
PAGEDATA:005C4534 15 00 00 00                   dd 15h
PAGEDATA:005C4538 0C 00 00 00                   dd 0Ch
PAGEDATA:005C453C 77 C7 58 00                   dd offset _PiControlHaltDevice@16 ; PiControlHaltDevice(x,x,x,x)
PAGEDATA:005C4540 16 00 00 00                   dd 16h
PAGEDATA:005C4544 0C 00 00 00                   dd 0Ch
PAGEDATA:005C4548 59 3B 4D 00                   dd offset _PiControlGetBlockedDriverData@16 ; PiControlGetBlockedDriverData(x,x,x,x)
PAGEDATA:005C454C 17 00 00 00                   dd 17h
PAGEDATA:005C4550 00 00 00 00                   dd 0
PAGEDATA:005C4554 00 00 00 00                   dd 0

*/

#include <sstream>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {

EXT_COMMAND(wa_pnptable, "Output kernel-mode nt!PlugPlayHandlerTable", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying nt!PlugPlayHandlerTable" << endlout;

    // PnpControlClass + Length + Routine
    unsigned __int32 size   = sizeof(unsigned __int32) + sizeof(unsigned __int32) + m_PtrSize;
    unsigned __int64 offset = 0;

    if ( !GetSymbolOffset("nt!PlugPlayHandlerTable", true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to find nt!PlugPlayHandlerTable" << endlerr;
        return;
    }

    out << wa::showplus << "nt!PlugPlayHandlerTable: " << std::hex << std::showbase << offset << endlout;

    auto display = WDbgArkAnalyzeBase::Create();

    if ( !display->AddRangeWhiteList("nt") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

    display->PrintHeader();

    try {
        for ( int i = 0; i < 0x100; i++ ) {
            ExtRemoteData pnp_table_entry_class(offset + i * size, static_cast<ULONG>(sizeof(unsigned __int32)));

            if ( pnp_table_entry_class.GetUlong() != i )    // check PnpControlClass
                break;

            unsigned __int64 init_offset = offset + i * size + sizeof(unsigned __int32) + sizeof(unsigned __int32);

            ExtRemoteData pnp_table_entry_routine(init_offset, m_PtrSize);
            display->Analyze(pnp_table_entry_routine.GetPtr(), "", "");
            display->PrintFooter();
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

}   // namespace wa
