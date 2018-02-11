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

/*
    nt!HalDispatchTable, nt!HalPrivateDispatchTable, nt!HalIommuDispatchTable, hal!HalpRegisteredInterruptControllers

    0: kd> dq HalpRegisteredInterruptControllers
    fffff803`0593a1b0  fffff7ef`40001478 fffff7ef`400018e8                          <-- LIST_ENTRY

    0: kd> dps fffff7ef`40001478 L20
    fffff7ef`40001478  fffff7ef`400016c0                                            <-- flink
    fffff7ef`40001480  fffff803`0593a1b0 hal!HalpRegisteredInterruptControllers     <-- blink
    fffff7ef`40001488  fffff7ef`400015c8                                            <-- n/a
    fffff7ef`40001490  00000000`00000028                                            <-- structure size
    fffff7ef`40001498  fffff803`058ef720 hal!HalpApicInitializeLocalUnit            <-- table start
    fffff7ef`400014a0  fffff803`058f2a90 hal!HalpApicInitializeIoUnit
    fffff7ef`400014a8  fffff803`058ef5d0 hal!HalpApicSetPriority
    fffff7ef`400014b0  fffff803`058eea40 hal!HalpApicGetLocalUnitError
    fffff7ef`400014b8  fffff803`058eea10 hal!HalpApicClearLocalUnitError
    fffff7ef`400014c0  00000000`00000000
    fffff7ef`400014c8  fffff803`058ef610 hal!HalpApicSetLogicalId
    fffff7ef`400014d0  00000000`00000000
    fffff7ef`400014d8  fffff803`0591a9d0 hal!HalpApicWriteEndOfInterrupt
    fffff7ef`400014e0  fffff803`05900100 hal!HalpApic1EndOfInterrupt
    fffff7ef`400014e8  fffff803`058efc70 hal!HalpApicSetLineState
    fffff7ef`400014f0  fffff803`058e7c50 hal!HalpApicRequestInterrupt
    fffff7ef`400014f8  fffff803`058edbe0 hal!HalpApicStartProcessor
    fffff7ef`40001500  fffff803`058e91b0 hal!HalpApicGenerateMessage
    fffff7ef`40001508  00000000`00000000
    fffff7ef`40001510  fffff803`0591ac50 hal!HalpApicSaveLocalInterrupts
    fffff7ef`40001518  fffff803`0591ab70 hal!HalpApicReplayLocalInterrupts
    fffff7ef`40001520  fffff803`0591a980 hal!HalpApicDeinitializeLocalUnit
    fffff7ef`40001528  00000000`00000000
    fffff7ef`40001530  fffff803`058e70f0 hal!HalpApicQueryAndGetSource              <-- table end
    fffff7ef`40001538  00000000`00000000
    fffff7ef`40001540  000000ff`00000002
    fffff7ef`40001548  0000000f`00000001
    fffff7ef`40001550  00000000`00000002
    fffff7ef`40001558  fffff7ef`40011298
    fffff7ef`40001560  fffff7ef`400117e8
    fffff7ef`40001568  fffff7ef`400115e0
    fffff7ef`40001570  fffff7ef`400115e0
*/

#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"
#include "memtable.hpp"
#include "memlist.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
typedef struct HalDispatchTableInfoTag {
    uint8_t hdt_count;      // HalDispatchTable table count
    uint8_t hpdt_count;     // HalPrivateDispatchTable table count
    uint8_t hiommu_count;   // HalIommuDispatch table count (W8.1+)
    uint8_t skip;           // Skip first N entries
} HalDispatchTableInfo;

using HalTableInfo = std::map<uint32_t, HalDispatchTableInfo>;
using HalTables = std::vector<WDbgArkMemTable>;
//////////////////////////////////////////////////////////////////////////
HalTableInfo GetHalTableInfo();
HalTables GetHalTables(const std::unique_ptr<WDbgArkSystemVer> &system_ver,
                       const std::shared_ptr<WDbgArkSymCache> &sym_cache);
//////////////////////////////////////////////////////////////////////////
EXT_COMMAND(wa_haltables, "Output kernel-mode HAL tables: "\
            "nt!HalDispatchTable, nt!HalPrivateDispatchTable, nt!HalIommuDispatchTable,"\
            "hal!HalpRegisteredInterruptControllers", "") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    out << wa::showplus << "Displaying HAL tables" << endlout;

    if ( !m_system_ver->IsInited() ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    auto hal_tables = GetHalTables(m_system_ver, m_sym_cache);

    try {
        for ( auto& table : hal_tables ) {
            const auto table_name = table.GetTableName();
            out << wa::showplus << table_name << ": " << std::hex << std::showbase << table.GetTableStart() << endlout;
            display->PrintHeader();

            WDbgArkMemTable::WalkResult result;

            if ( table.Walk(&result) != false ) {
                for ( const auto& address : result ) {
                    display->Analyze(address, "", "");
                    display->PrintFooter();
                }
            } else {
                err << wa::showminus << __FUNCTION__ << ": failed to walk " << table_name << endlerr;
            }
        }
    } catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

/* { HalDispatchTable table count
     HalPrivateDispatchTable table count
     HalIommuDispatchTable table count (W8.1+)
     Skip first N entries
   }
*/
HalTableInfo GetHalTableInfo() {
    return { {
        { WXP_VER, { 0x15, 0x12, 0x0, 0x1 } },
        { W2K3_VER, { 0x15, 0x13, 0x0, 0x1 } },
        { VISTA_RTM_VER, { 0x16, 0x1B, 0x0, 0x1 } },
        { VISTA_SP1_VER, { 0x18, 0x22, 0x0, 0x1 } },
        { VISTA_SP2_VER, { 0x17, 0x23, 0x0, 0x1 } },
        { W7RTM_VER, { 0x16, 0x2D, 0x0, 0x1 } },
        { W7SP1_VER, { 0x16, 0x2D, 0x0, 0x1 } },
        { W8RTM_VER, { 0x16, 0x5A, 0x0, 0x1 } },
        { W81RTM_VER, { 0x16, 0x69, 0x0B, 0x1 } },
        { W10RTM_VER, { 0x16, 0x71, 0x10, 0x1 } },
        { W10TH2_VER, { 0x16, 0x71, 0x10, 0x1 } },
        { W10RS1_VER, { 0x16, 0x7C, 0x11, 0x1 } },
        { W10RS2_VER, { 0x16, 0x7F, 0x13, 0x1 } },
        { W10RS3_VER, { 0x16, 0x89, 0x13, 0x1 } }
        } };
}

HalTables GetHalTables(const std::unique_ptr<WDbgArkSystemVer> &system_ver,
                       const std::shared_ptr<WDbgArkSymCache> &sym_cache) {
    HalTables hal_tables{};

    const auto hal_tbl_info = GetHalTableInfo();
    const auto it = hal_tbl_info.find(system_ver->GetStrictVer());

    if ( it == std::end(hal_tbl_info) ) {
        err << wa::showminus << __FUNCTION__ << ": unable to correlate internal info with the minor build" << endlerr;
        return hal_tables;
    }

    const auto [version, info] = *it;

    WDbgArkMemTable table_hdt(sym_cache, "nt!HalDispatchTable");

    if ( table_hdt.IsValid() ) {
        table_hdt.SetTableSkipStart(info.skip * g_Ext->m_PtrSize);
        table_hdt.SetTableCount(info.hdt_count);
        table_hdt.SetRoutineDelta(g_Ext->m_PtrSize);
        table_hdt.SetCollectNull(true);

        hal_tables.push_back(table_hdt);
    } else {
        err << wa::showminus << __FUNCTION__ << ": unable to find nt!HalDispatchTable" << endlerr;
    }

    WDbgArkMemTable table_hpdt(sym_cache, "nt!HalPrivateDispatchTable");

    if ( table_hpdt.IsValid() ) {
        table_hpdt.SetTableSkipStart(info.skip * g_Ext->m_PtrSize);
        table_hpdt.SetTableCount(info.hpdt_count);
        table_hpdt.SetRoutineDelta(g_Ext->m_PtrSize);
        table_hpdt.SetCollectNull(true);

        hal_tables.push_back(table_hpdt);
    } else {
        err << wa::showminus << __FUNCTION__ << ": unable to find nt!HalPrivateDispatchTable" << endlerr;
    }

    if ( system_ver->GetStrictVer() >= W81RTM_VER ) {
        WDbgArkMemTable table_hiommu(sym_cache, 0ULL);

        table_hiommu.SetTableStart("nt!HalIommuDispatchTable");

        if ( table_hiommu.IsValid() ) {
            table_hiommu.SetTableCount(info.hiommu_count);
            table_hiommu.SetRoutineDelta(g_Ext->m_PtrSize);
            table_hiommu.SetCollectNull(true);

            hal_tables.push_back(table_hiommu);
        } else {
            err << wa::showminus << __FUNCTION__ << ": unable to find nt!HalIommuDispatchTable" << endlerr;
        }
    }

    if ( system_ver->GetStrictVer() >= W8RTM_VER ) {
        std::string list_name("hal!HalpRegisteredInterruptControllers");
        WDbgArkMemList list_hric(sym_cache, list_name);

        if ( list_hric.IsValid() ) {
            WDbgArkMemList::WalkResult list_result;
            const auto le_size = sym_cache->GetTypeSize("nt!_LIST_ENTRY");

            if ( list_hric.WalkNodes(&list_result) != false ) {
                size_t i = 0;

                for ( const auto& node : list_result ) {
                    WDbgArkMemTable table_hric(sym_cache, node);

                    if ( table_hric.IsValid() ) {
                        table_hric.SetTableName(list_name + "[" + std::to_string(i) + "]");
                        table_hric.SetTableSkipStart(le_size + 2 * g_Ext->m_PtrSize);
                        table_hric.SetTableCount(20);
                        table_hric.SetRoutineDelta(g_Ext->m_PtrSize);
                        table_hric.SetCollectNull(true);

                        hal_tables.push_back(table_hric);
                    }

                    ++i;
                }
            } else {
                err << wa::showminus << __FUNCTION__ << ": failed to walk " << list_hric.GetListHeadName() << endlerr;
            }
        } else {
            err << wa::showminus << __FUNCTION__ << ": unable to find " << list_hric.GetListHeadName() << endlerr;
        }
    }

    return hal_tables;
}

}   // namespace wa
