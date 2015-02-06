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

#include <string>
#include <algorithm>
#include <memory>

#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "symbols.hpp"

EXT_DECLARE_GLOBALS();

namespace wa {

const std::string WDbgArk::m_ms_public_symbols_server = "http://msdl.microsoft.com/download/symbols";

WDbgArk::WDbgArk() : m_inited(false),
                     m_is_cur_machine64(false),
                     m_platform_id(0),
                     m_major_build(0),
                     m_minor_build(0),
                     m_strict_minor_build(0),
                     m_service_pack_number(0),
                     m_system_cb_commands(),
                     m_callout_names(),
                     m_gdt_selectors(),
                     m_hal_tbl_info(),
                     m_known_windows_builds(),
                     m_synthetic_symbols(),
                     m_obj_helper(nullptr),
                     m_color_hack(nullptr),
                     m_dummy_pdb(nullptr),
                     out(),
                     warn(),
                     err() {
#if defined(_DEBUG)
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
    // _CrtSetBreakAlloc( 143 );
#endif  // _DEBUG
}

WDbgArk::~WDbgArk() {
    // RemoveSyntheticSymbols();  //    TODO(swwwolf): already dead on unload

#if defined(_DEBUG)
    _CrtDumpMemoryLeaks();
#endif  // _DEBUG
}

bool WDbgArk::Init() {
    if ( IsInited() )
        return true;

    m_is_cur_machine64 = IsCurMachine64();

    m_Symbols->Reload("");  // revise debuggee modules list

    if ( !CheckSymbolsPath(m_ms_public_symbols_server, true) )
        warn << __FUNCTION__ ": CheckSymbolsPath failed" << endlwarn;

    m_obj_helper = std::unique_ptr<WDbgArkObjHelper>(new WDbgArkObjHelper);

    if ( !m_obj_helper->IsInited() )
        warn << __FUNCTION__ ": WDbgArkObjHelper init failed" << endlwarn;

    m_color_hack = std::unique_ptr<WDbgArkColorHack>(new WDbgArkColorHack);

    if ( !m_color_hack->IsInited() )
        warn << __FUNCTION__ ": WDbgArkColorHack init failed" << endlwarn;

    m_dummy_pdb = std::unique_ptr<WDbgArkDummyPdb>(new WDbgArkDummyPdb);

    if ( !m_dummy_pdb->IsInited() )
        warn << __FUNCTION__ ": WDbgArkDummyPdb init failed" << endlwarn;

    // get system version
    HRESULT result = m_Control->GetSystemVersion(reinterpret_cast<PULONG>(&m_platform_id),
                                                 reinterpret_cast<PULONG>(&m_major_build),
                                                 reinterpret_cast<PULONG>(&m_minor_build),
                                                 NULL,
                                                 0,
                                                 NULL,
                                                 reinterpret_cast<PULONG>(&m_service_pack_number),
                                                 NULL,
                                                 0,
                                                 NULL);

    if ( !SUCCEEDED(result) )
        warn << __FUNCTION__ ": GetSystemVersion failed with result = " << result << endlwarn;

    m_strict_minor_build = GetWindowsStrictMinorBuild();
    InitKnownWindowsBuilds();
    CheckWindowsBuild();

    InitCallbackCommands();
    InitCalloutNames();
    InitGDTSelectors();
    InitHalTables();

    if ( !FindDbgkLkmdCallbackArray() )
        warn << __FUNCTION__ ": FindDbgkLkmdCallbackArray failed" << endlwarn;

    m_inited = true;

    return m_inited;
}

// TODO(swwwolf): optimize by calculating offsets in constructor only once
void WDbgArk::InitCallbackCommands(void) {
    m_system_cb_commands.insert(callbacksInfo::value_type("image",
                                                          SystemCbCommand("nt!PspLoadImageNotifyRoutineCount",
                                                                          "nt!PspLoadImageNotifyRoutine",
                                                                          0)));

    m_system_cb_commands.insert(callbacksInfo::value_type("process",
                                                          SystemCbCommand("nt!PspCreateProcessNotifyRoutineCount",
                                                                          "nt!PspCreateProcessNotifyRoutine",
                                                                          0)));

    m_system_cb_commands.insert(callbacksInfo::value_type("thread",
                                                          SystemCbCommand("nt!PspCreateThreadNotifyRoutineCount",
                                                                          "nt!PspCreateThreadNotifyRoutine",
                                                                          0)));

    m_system_cb_commands.insert(callbacksInfo::value_type("registry",
                                                          SystemCbCommand("nt!CmpCallBackCount",
                                                                          "nt!CmpCallBackVector",
                                                                          GetCmCallbackItemFunctionOffset())));

    m_system_cb_commands.insert(callbacksInfo::value_type("bugcheck",
                                                          SystemCbCommand("",
                                                                          "nt!KeBugCheckCallbackListHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("bugcheckreason",
                                                          SystemCbCommand("",
                                                                          "nt!KeBugCheckReasonCallbackListHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("bugcheckaddpages",
                                                          SystemCbCommand("",
                                                                          "nt!KeBugCheckAddPagesCallbackListHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("powersetting",
                                                          SystemCbCommand("",
                                                                          "nt!PopRegisteredPowerSettingCallbacks",
                                                                          GetPowerCallbackItemFunctionOffset())));

    m_system_cb_commands.insert(callbacksInfo::value_type("kdppower",
                                                          SystemCbCommand("",
                                                                          "nt!KdpPowerListHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("callbackdir", SystemCbCommand()));

    m_system_cb_commands.insert(callbacksInfo::value_type("shutdown",
                                                          SystemCbCommand("",
                                                                          "nt!IopNotifyShutdownQueueHead",
                                                                          0)));

    m_system_cb_commands.insert(callbacksInfo::value_type("shutdownlast",
                                                          SystemCbCommand("",
                                                                          "nt!IopNotifyLastChanceShutdownQueueHead",
                                                                          0)));

    m_system_cb_commands.insert(callbacksInfo::value_type("drvreinit",
                                                          SystemCbCommand("",
                                                                          "nt!IopDriverReinitializeQueueHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY") + m_PtrSize)));

    m_system_cb_commands.insert(callbacksInfo::value_type("bootdrvreinit",
                                                          SystemCbCommand("",
                                                                          "nt!IopBootDriverReinitializeQueueHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY") + m_PtrSize)));

    m_system_cb_commands.insert(callbacksInfo::value_type("fschange",
                                                          SystemCbCommand("",
                                                                          "nt!IopFsNotifyChangeQueueHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY") + m_PtrSize)));

    m_system_cb_commands.insert(callbacksInfo::value_type("nmi",
                                                          SystemCbCommand("",
                                                                          "nt!KiNmiCallbackListHead",
                                                                          m_PtrSize)));

    m_system_cb_commands.insert(callbacksInfo::value_type("logonsessionroutine",
                                                          SystemCbCommand("",
                                                                          "nt!SeFileSystemNotifyRoutinesHead",
                                                                          m_PtrSize)));

    m_system_cb_commands.insert(callbacksInfo::value_type("prioritycallback",
                                                          SystemCbCommand("nt!IopUpdatePriorityCallbackRoutineCount",
                                                                          "nt!IopUpdatePriorityCallbackRoutine",
                                                                          0)));

    m_system_cb_commands.insert(callbacksInfo::value_type("pnp", SystemCbCommand()));

    // actually just a pointer
    m_system_cb_commands.insert(callbacksInfo::value_type("lego",
                                                          SystemCbCommand("",
                                                                          "nt!PspLegoNotifyRoutine",
                                                                          0)));

    m_system_cb_commands.insert(callbacksInfo::value_type("debugprint",
                                                          SystemCbCommand("",
                                                                          "nt!RtlpDebugPrintCallbackList",
                                                                          GetTypeSize("nt!_LIST_ENTRY"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("alpcplog",
                                                          SystemCbCommand("",
                                                                          "nt!AlpcpLogCallbackListHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("empcb",
                                                          SystemCbCommand("",
                                                                          "nt!EmpCallbackListHead",
                                                                          GetTypeSize("nt!_GUID"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("ioperf",
                                                          SystemCbCommand("",
                                                                          "nt!IopPerfIoTrackingListHead",
                                                                          GetTypeSize("nt!_LIST_ENTRY"))));

    m_system_cb_commands.insert(callbacksInfo::value_type("dbgklkmd",
                                                          SystemCbCommand("",
                                                                          "nt!DbgkLkmdCallbackArray",
                                                                          0)));

    unsigned __int32 timer_routine_offset = 0;

    if ( GetFieldOffset("nt!_IO_TIMER", "TimerRoutine", reinterpret_cast<PULONG>(&timer_routine_offset)) != 0 ) {
        warn << __FUNCTION__ << ": GetFieldOffset failed with nt!_IO_TIMER.TimerRoutine" << endlwarn;
    } else {
        m_system_cb_commands.insert(callbacksInfo::value_type("ioptimer",
                                                              SystemCbCommand("",
                                                                              "nt!IopTimerQueueHead",
                                                                              timer_routine_offset)));
    }
}

void WDbgArk::InitCalloutNames(void) {
    if ( m_minor_build < W8RTM_VER ) {
        m_callout_names.push_back("nt!PspW32ProcessCallout");
        m_callout_names.push_back("nt!PspW32ThreadCallout");
        m_callout_names.push_back("nt!ExGlobalAtomTableCallout");
        m_callout_names.push_back("nt!KeGdiFlushUserBatch");
        m_callout_names.push_back("nt!PopEventCallout");
        m_callout_names.push_back("nt!PopStateCallout");
        m_callout_names.push_back("nt!PspW32JobCallout");
        m_callout_names.push_back("nt!ExDesktopOpenProcedureCallout");
        m_callout_names.push_back("nt!ExDesktopOkToCloseProcedureCallout");
        m_callout_names.push_back("nt!ExDesktopCloseProcedureCallout");
        m_callout_names.push_back("nt!ExDesktopDeleteProcedureCallout");
        m_callout_names.push_back("nt!ExWindowStationOkToCloseProcedureCallout");
        m_callout_names.push_back("nt!ExWindowStationCloseProcedureCallout");
        m_callout_names.push_back("nt!ExWindowStationDeleteProcedureCallout");
        m_callout_names.push_back("nt!ExWindowStationParseProcedureCallout");
        m_callout_names.push_back("nt!ExWindowStationOpenProcedureCallout");
        m_callout_names.push_back("nt!IopWin32DataCollectionProcedureCallout");
        m_callout_names.push_back("nt!PopWin32InfoCallout");
    }
}

void WDbgArk::InitGDTSelectors(void) {
    if ( m_is_cur_machine64 ) {
        m_gdt_selectors.push_back(KGDT64_NULL);
        m_gdt_selectors.push_back(KGDT64_R0_CODE);
        m_gdt_selectors.push_back(KGDT64_R0_DATA);
        m_gdt_selectors.push_back(KGDT64_R3_CMCODE);
        m_gdt_selectors.push_back(KGDT64_R3_DATA);
        m_gdt_selectors.push_back(KGDT64_R3_CODE);
        m_gdt_selectors.push_back(KGDT64_SYS_TSS);
        m_gdt_selectors.push_back(KGDT64_R3_CMTEB);
    } else {
        m_gdt_selectors.push_back(KGDT_R0_CODE);
        m_gdt_selectors.push_back(KGDT_R0_DATA);
        m_gdt_selectors.push_back(KGDT_R3_CODE);
        m_gdt_selectors.push_back(KGDT_R3_DATA);
        m_gdt_selectors.push_back(KGDT_TSS);
        m_gdt_selectors.push_back(KGDT_R0_PCR);
        m_gdt_selectors.push_back(KGDT_R3_TEB);
        m_gdt_selectors.push_back(KGDT_LDT);
        m_gdt_selectors.push_back(KGDT_DF_TSS);
        m_gdt_selectors.push_back(KGDT_NMI_TSS);
        m_gdt_selectors.push_back(KGDT_GDT_ALIAS);
        m_gdt_selectors.push_back(KGDT_CDA16);
        m_gdt_selectors.push_back(KGDT_CODE16);
        m_gdt_selectors.push_back(KGDT_STACK16);
    }
}

void WDbgArk::InitHalTables(void) {
    m_hal_tbl_info.insert(haltblInfo::value_type(WXP_VER, HalDispatchTablesInfo(0x15, 0x12, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(W2K3_VER, HalDispatchTablesInfo(0x16, 0x14, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(VISTA_RTM_VER, HalDispatchTablesInfo(0x16, 0x1B, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(VISTA_SP1_VER, HalDispatchTablesInfo(0x18, 0x21, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(VISTA_SP2_VER, HalDispatchTablesInfo(0x17, 0x24, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(W7RTM_VER, HalDispatchTablesInfo(0x16, 0x2E, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(W7SP1_VER, HalDispatchTablesInfo(0x16, 0x2D, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(W8RTM_VER, HalDispatchTablesInfo(0x16, 0x5A, 0x0, 0x1)));
    m_hal_tbl_info.insert(haltblInfo::value_type(W81RTM_VER, HalDispatchTablesInfo(0x16, 0x69, 0x0B, 0x1)));
}

void WDbgArk::InitKnownWindowsBuilds(void) {
    m_known_windows_builds.insert(WXP_VER);
    m_known_windows_builds.insert(W2K3_VER);
    m_known_windows_builds.insert(VISTA_RTM_VER);
    m_known_windows_builds.insert(VISTA_SP1_VER);
    m_known_windows_builds.insert(VISTA_SP2_VER);
    m_known_windows_builds.insert(W7RTM_VER);
    m_known_windows_builds.insert(W7SP1_VER);
    m_known_windows_builds.insert(W8RTM_VER);
    m_known_windows_builds.insert(W81RTM_VER);
}

void WDbgArk::CheckWindowsBuild(void) {
    if ( m_known_windows_builds.find(m_minor_build) == m_known_windows_builds.end() ) {
        warn << __FUNCTION__ << ": unknown Windows version. Be careful and look sharp!" << endlwarn;
    }
}

void WDbgArk::WalkAnyListWithOffsetToRoutine(const std::string &list_head_name,
                                             const unsigned __int64 offset_list_head,
                                             const unsigned __int32 link_offset,
                                             const bool is_double,
                                             const unsigned __int32 offset_to_routine,
                                             const std::string &type,
                                             const std::string &ext_info,
                                             walkresType* output_list) {
    unsigned __int64 offset               = offset_list_head;
    unsigned __int64 list_head_offset_out = 0;

    if ( !offset_to_routine ) {
        err << __FUNCTION__ << ": invalid parameter" << endlerr;
        return;
    }

    if ( !offset ) {
        if ( !GetSymbolOffset(list_head_name.c_str(), true, &offset) ) {
            err << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
            return;
        } else {
            list_head_offset_out = offset;
        }
    }

    try {
        ExtRemoteList list_head(offset, link_offset, is_double);

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
            unsigned __int64 node = list_head.GetNodeOffset();
            ExtRemoteData structure_data(node + offset_to_routine, m_PtrSize);

            unsigned __int64 routine = structure_data.GetPtr();

            if ( routine ) {
                OutputWalkInfo info;

                info.address = routine;
                info.type = type;
                info.info = ext_info;
                info.list_head_name = list_head_name;
                info.object_address = node;
                info.list_head_address = list_head_offset_out;

                output_list->push_back(info);
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkAnyListWithOffsetToObjectPointer(const std::string &list_head_name,
                                                   const unsigned __int64 offset_list_head,
                                                   const bool is_double,
                                                   const unsigned __int32 offset_to_object_pointer,
                                                   void* context,
                                                   pfn_any_list_w_pobject_walk_callback_routine callback) {
    unsigned __int64 offset = offset_list_head;

    if ( !offset_to_object_pointer ) {
        err << __FUNCTION__ << ": invalid parameter offset_to_object_pointer" << endlerr;
        return;
    }

    if ( !offset && !GetSymbolOffset(list_head_name.c_str(), true, &offset) ) {
        err << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
        return;
    }

    try {
        ExtRemoteList list_head(offset, 0, is_double);

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
            ExtRemoteData object_pointer(list_head.GetNodeOffset() + offset_to_object_pointer, m_PtrSize);

            if ( !SUCCEEDED(callback(this, object_pointer, context)) ) {
                err << __FUNCTION__ << ": error while invoking callback" << endlerr;
                return;
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkDirectoryObject(const unsigned __int64 directory_address,
                                  void* context,
                                  pfn_object_directory_walk_callback_routine callback) {
    if ( !directory_address ) {
        err << __FUNCTION__ << ": invalid directory address" << endlerr;
        return;
    }

    if ( !callback ) {
        err << __FUNCTION__ << ": invalid callback address" << endlerr;
        return;
    }

    try {
        ExtRemoteTyped directory_object("nt!_OBJECT_DIRECTORY", directory_address, false, NULL, NULL);
        ExtRemoteTyped buckets = directory_object.Field("HashBuckets");

        const unsigned __int32 num_buckets = buckets.GetTypeSize() / m_PtrSize;

        for ( __int64 i = 0; i < num_buckets; i++ ) {
            for ( ExtRemoteTyped directory_entry = *buckets[i];
                  directory_entry.m_Offset;
                  directory_entry = *directory_entry.Field("ChainLink") ) {
                ExtRemoteTyped object = *directory_entry.Field("Object");

                if ( !SUCCEEDED(callback(this, object, context)) ) {
                    err << __FUNCTION__ << ": error while invoking callback" << endlerr;
                    return;
                }
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkDeviceNode(const unsigned __int64 device_node_address,
                             void* context,
                             pfn_device_node_walk_callback_routine callback) {
    unsigned __int64 offset = device_node_address;

    if ( !callback ) {
        err << __FUNCTION__ << ": invalid callback address" << endlerr;
        return;
    }

    try {
        if ( !offset ) {
            if ( !GetSymbolOffset("nt!IopRootDeviceNode", true, &offset) ) {
                err << __FUNCTION__ << ": failed to get nt!IopRootDeviceNode" << endlerr;
                return;
            } else {
                ExtRemoteData device_node_ptr(offset, m_PtrSize);
                offset = device_node_ptr.GetPtr();
            }
        }

        ExtRemoteTyped device_node("nt!_DEVICE_NODE", offset, false, NULL, NULL);

        for ( ExtRemoteTyped child_node = *device_node.Field("Child");
              child_node.m_Offset;
              child_node = *child_node.Field("Sibling") ) {
            if ( !SUCCEEDED(callback(this, child_node, context)) ) {
                err << __FUNCTION__ << ": error while invoking callback" << endlerr;
                return;
            }

            WalkDeviceNode(child_node.m_Offset, context, callback);
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkAnyTable(const unsigned __int64 table_start,
                           const unsigned __int32 offset_table_skip_start,
                           const unsigned __int32 table_count,
                           const std::string &type,
                           walkresType* output_list,
                           bool break_on_null,
                           bool collect_null) {
    unsigned __int64 offset = table_start + offset_table_skip_start;

    try {
        for ( unsigned __int32 i = 0; i < table_count; i++ ) {
            ExtRemoteData data(offset + i * m_PtrSize, m_PtrSize);

            if ( data.GetPtr() || collect_null ) {
                OutputWalkInfo info;

                info.address = data.GetPtr();
                info.type = type;
                info.info.clear();
                info.list_head_name.clear();
                info.object_address = 0ULL;
                info.list_head_address = 0ULL;

                output_list->push_back(info);
            } else if ( break_on_null ) {
                break;
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::AddSymbolPointer(const std::string &symbol_name,
                               const std::string &type,
                               const std::string &additional_info,
                               walkresType* output_list) {
    unsigned __int64 offset = 0;

    try {
        if ( GetSymbolOffset(symbol_name.c_str(), true, &offset) ) {
            unsigned __int64 symbol_offset = offset;

            ExtRemoteData routine_ptr(offset, m_PtrSize);
            offset = routine_ptr.GetPtr();

            if ( offset ) {
                OutputWalkInfo info;

                info.address = offset;
                info.type = type;
                info.info = additional_info;
                info.list_head_name = symbol_name;
                info.object_address = 0ULL;
                info.list_head_address = symbol_offset;

                output_list->push_back(info);
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

// TODO(swwwolf): get human disassembler, not this piece of shit with strings
bool WDbgArk::FindDbgkLkmdCallbackArray() {
    #define MAX_INSN_LENGTH 15

    unsigned __int64 offset = 0;
    bool             result = false;

    if ( m_minor_build < W7RTM_VER ) {
        out << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return false;
    }

    if ( GetSymbolOffset("nt!DbgkLkmdCallbackArray", true, &offset) )
        return true;

    if ( !GetSymbolOffset("nt!DbgkLkmdUnregisterCallback", true, &offset) ) {
        err << __FUNCTION__ << ": can't find nt!DbgkLkmdUnregisterCallback" << endlerr;
        return false;
    }

    try {
        ExtRemoteData test_offset(offset, m_PtrSize);
    }
    catch( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return false;
    }

    unsigned __int64 cur_pointer = offset;
    unsigned __int64 end         = cur_pointer + MAX_INSN_LENGTH * 20;

    std::unique_ptr<char[]> disasm_buf(new char[0x100]);

    unsigned __int32 asm_options;

    if ( !SUCCEEDED(m_Control3->GetAssemblyOptions(reinterpret_cast<PULONG>(&asm_options))) )
        warn << __FUNCTION__ << ": failed to get assembly options" << endlwarn;

    if ( !SUCCEEDED(m_Control3->SetAssemblyOptions(DEBUG_ASMOPT_NO_CODE_BYTES)) )
        warn << __FUNCTION__ << ": failed to set assembly options" << endlwarn;

    while ( cur_pointer < end ) {
        HRESULT disasm_result = m_Control->Disassemble(cur_pointer,
                                                       0,
                                                       disasm_buf.get(),
                                                       0x100,
                                                       nullptr,
                                                       &cur_pointer);

        if ( !SUCCEEDED(disasm_result) ) {
            err << __FUNCTION__ " : disassembly failed at " << std::hex << std::showbase << cur_pointer << endlerr;
            break;
        }

        std::string disasm   = disasm_buf.get();
        size_t      posstart = 0;
        size_t      posend   = 0;
        size_t      pos      = 0;

        // TODO(swwwolf): regexp?
        if ( m_is_cur_machine64 ) {
            pos = disasm.find("lea", 0);

            if ( pos == std::string::npos )
                continue;

            pos = disasm.find(",[", pos);

            if ( pos == std::string::npos )
                continue;

            posstart = disasm.find("(", pos);

            if ( posstart == std::string::npos )
                continue;

            posend = disasm.find(")", posstart);

            if ( posstart == std::string::npos )
                continue;
        } else {
            pos = disasm.find("mov", 0);

            if ( pos == std::string::npos )
                continue;

            pos = disasm.find(",offset", pos);

            if ( pos == std::string::npos )
                continue;

            posstart = disasm.find("(", pos);

            if ( posstart == std::string::npos )
                continue;

            posend = disasm.find(")", posstart);

            if ( posstart == std::string::npos )
                continue;
        }

        std::string string_value(disasm.substr(posstart + 1, posend - posstart - 1));

        try {
            unsigned __int64 ret_address = g_Ext->EvalExprU64(string_value.c_str());

            // do not reload nt module after that
            DEBUG_MODULE_AND_ID id;

            HRESULT hresult = m_Symbols3->AddSyntheticSymbol(ret_address,
                                                             m_PtrSize,
                                                             "DbgkLkmdCallbackArray",
                                                             DEBUG_ADDSYNTHSYM_DEFAULT,
                                                             &id);

            if ( !SUCCEEDED(hresult) ) {
                err << __FUNCTION__ << ": failed to add synthetic symbol DbgkLkmdCallbackArray" << endlerr;
            } else {
                m_synthetic_symbols.push_back(id);
                result = true;
            }
        }
        catch ( const ExtStatusException &Ex ) {
            err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        }

        break;
    }

    if ( !SUCCEEDED(m_Control3->SetAssemblyOptions(asm_options)) )
        warn << __FUNCTION__ << ": failed to set assembly options" << endlwarn;

    return result;
}

unsigned __int32 WDbgArk::GetWindowsStrictMinorBuild(void) const {
    if ( m_minor_build <= WXP_VER )
        return WXP_VER;
    else if ( m_minor_build > WXP_VER && m_minor_build <= W2K3_VER )
        return W2K3_VER;
    else if ( m_minor_build > W2K3_VER && m_minor_build <= VISTA_RTM_VER )
        return VISTA_RTM_VER;
    else if ( m_minor_build > VISTA_SP1_VER && m_minor_build <= VISTA_SP2_VER )
        return VISTA_SP2_VER;
    else if ( m_minor_build > VISTA_SP2_VER && m_minor_build <= W7RTM_VER )
        return W7RTM_VER;
    else if ( m_minor_build > W7RTM_VER && m_minor_build <= W7SP1_VER )
        return W7SP1_VER;
    else if ( m_minor_build > W7SP1_VER && m_minor_build <= W8RTM_VER )
        return W8RTM_VER;
    else if ( m_minor_build > W8RTM_VER && m_minor_build <= W81RTM_VER )
        return W81RTM_VER;

    return 0UL;
}

void WDbgArk::RemoveSyntheticSymbols(void) {
    for ( DEBUG_MODULE_AND_ID id : m_synthetic_symbols ) {
        if ( !SUCCEEDED(m_Symbols3->RemoveSyntheticSymbol(&id)) ) {
            warn << __FUNCTION__ << ": failed to remove synthetic symbol ";
            warn << std::hex << std::showbase << id.Id << endlwarn;
        }
    }
}

}   // namespace wa
