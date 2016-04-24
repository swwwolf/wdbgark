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

// Workaround for engextcpp.lib
// 1>engextcpp.lib(engextcpp.obj) : error LNK2019: unresolved external symbol _vsnprintf referenced in function
// "public: void __cdecl ExtExtension::AppendStringVa(char const *,char *)"
// (?AppendStringVa@ExtExtension@@QEAAXPEBDPEAD@Z)
// TODO(swwwolf): remove after VS 2015 fix
// #define STRSAFE_LIB_IMPL
// #include <strsafe.h>
// https://connect.microsoft.com/VisualStudio/feedback/details/2078387/engextcpp-lib-unresolved-external-symbol-vsnprintf-referenced-in-function
// fixed by linking with legacy_stdio_definitions.lib (OMFG, MS)

#include <string>
#include <algorithm>
#include <memory>

#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "symbols.hpp"
#include "systemcb.hpp"

EXT_DECLARE_GLOBALS();

namespace wa {

WDbgArk::WDbgArk() {
    int flag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
    flag |= _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF;
    _CrtSetDbgFlag(flag);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
    // _CrtSetBreakAlloc(3173761);
    // (int*){,,msvcr120d.dll}_crtBreakAlloc in Watch window
}

bool WDbgArk::Init() {
    if ( IsInited() )
        return true;

    if ( m_Client->QueryInterface(__uuidof(IDebugSymbols3), reinterpret_cast<void**>(&m_symbols3_iface)) != S_OK ) {
        m_symbols3_iface.Set(nullptr);
        err << wa::showminus << __FUNCTION__ << ": Failed to initialize interface" << endlerr;
    }

    m_is_cur_machine64 = IsCurMachine64();

    // get system version
    m_system_ver.reset(new WDbgArkSystemVer);

    if ( !m_system_ver->IsInited() ) {
        err << wa::showminus << __FUNCTION__ ": WDbgArkSystemVer init failed" << endlerr;
        return false;
    } else {
        m_system_ver->CheckWindowsBuild();
    }

    m_Symbols->Reload("");  // revise debuggee modules list

    m_symbols_base.reset(new WDbgArkSymbolsBase);

    if ( !m_symbols_base->CheckMsSymbolsPath() )
        warn << wa::showqmark << __FUNCTION__ ": CheckMsSymbolsPath failed" << endlwarn;

    // it's a bad idea to do this in constructor's initialization list 'coz global class uninitialized
    m_obj_helper.reset(new WDbgArkObjHelper(m_sym_cache));

    if ( !m_obj_helper->IsInited() )
        warn << wa::showqmark << __FUNCTION__ ": WDbgArkObjHelper init failed" << endlwarn;

    m_color_hack.reset(new WDbgArkColorHack);

    if ( !m_color_hack->IsInited() )
        warn << wa::showqmark << __FUNCTION__ ": WDbgArkColorHack init failed" << endlwarn;

    m_dummy_pdb.reset(new WDbgArkDummyPdb);

    if ( !m_dummy_pdb->IsInited() )
        warn << wa::showqmark << __FUNCTION__ ": WDbgArkDummyPdb init failed" << endlwarn;

    InitScanCommands();
    InitCallbackCommands();

    if ( m_system_ver->GetStrictVer() >= W7RTM_VER && !FindDbgkLkmdCallbackArray() )
        warn << wa::showqmark << __FUNCTION__ ": FindDbgkLkmdCallbackArray failed" << endlwarn;

    if ( m_system_ver->GetStrictVer() >= W10RTM_VER && !FindMiApiSetSchema() )
        warn << wa::showqmark << __FUNCTION__ ": FindMiApiSetSchema failed" << endlwarn;

    return (m_inited = true);
}

void WDbgArk::InitScanCommands() {
    m_scan_commands = {
        { "!wa_ssdt", std::bind(&WDbgArk::wa_ssdt, this) },
        { "!wa_w32psdt", std::bind(&WDbgArk::wa_w32psdt, this) },
        { "!wa_w32psdtflt", std::bind(&WDbgArk::wa_w32psdtflt, this) },
        { "!wa_idt", std::bind(&WDbgArk::wa_idt, this) },
        { "!wa_gdt", std::bind(&WDbgArk::wa_gdt, this) },
        { "!wa_checkmsr", std::bind(&WDbgArk::wa_checkmsr, this) },
        { "!wa_systemcb", std::bind(&WDbgArk::wa_systemcb, this) },
        { "!wa_chknirvana", std::bind(&WDbgArk::wa_chknirvana, this) },
        { "!wa_objtype", std::bind(&WDbgArk::wa_objtype, this) },
        { "!wa_objtypeidx", std::bind(&WDbgArk::wa_objtypeidx, this) },
        { "!wa_objtypecb", std::bind(&WDbgArk::wa_objtypecb, this) },
        { "!wa_callouts", std::bind(&WDbgArk::wa_callouts, this) },
        { "!wa_pnptable", std::bind(&WDbgArk::wa_pnptable, this) },
        { "!wa_crashdmpcall", std::bind(&WDbgArk::wa_crashdmpcall, this) },
        { "!wa_haltables", std::bind(&WDbgArk::wa_haltables, this) },
        { "!wa_psppico", std::bind(&WDbgArk::wa_psppico, this) },
        { "!wa_ciinfo", std::bind(&WDbgArk::wa_ciinfo, this) },
        { "!wa_cicallbacks", std::bind(&WDbgArk::wa_cicallbacks, this) },
        { "!wa_drvmajor", std::bind(&WDbgArk::wa_drvmajor, this) }
    };
}

void WDbgArk::InitCallbackCommands() {
    uint32_t timer_routine_offset = 0;

    if ( GetFieldOffset("nt!_IO_TIMER", "TimerRoutine", reinterpret_cast<PULONG>(&timer_routine_offset)) != 0 )
        warn << wa::showqmark << __FUNCTION__ << ": GetFieldOffset failed with nt!_IO_TIMER.TimerRoutine" << endlwarn;

    uint32_t le_size = GetTypeSize("nt!_LIST_ENTRY");

    m_system_cb_commands = { {
        { "image", { "nt!PspLoadImageNotifyRoutineCount", "nt!PspLoadImageNotifyRoutine", 0, 0, 0 } },
        { "process", { "nt!PspCreateProcessNotifyRoutineCount", "nt!PspCreateProcessNotifyRoutine", 0, 0, 0 } },
        { "thread", { "nt!PspCreateThreadNotifyRoutineCount", "nt!PspCreateThreadNotifyRoutine", 0, 0, 0 } },
        { "registry", { "nt!CmpCallBackCount", "nt!CmpCallBackVector", GetCmCallbackItemFunctionOffset(), 0, 0 } },
        { "bugcheck", { "", "nt!KeBugCheckCallbackListHead", le_size, 0, 0 } },
        { "bugcheckreason", { "", "nt!KeBugCheckReasonCallbackListHead", le_size, 0, 0 } },
        { "bugcheckaddpages", { "", "nt!KeBugCheckAddPagesCallbackListHead", le_size, 0, 0 } },
        { "bugcheckaddremovepages", { "", "nt!KeBugCheckAddRemovePagesCallbackListHead", le_size, 0, 0 } },
        { "powersetting", { "", "nt!PopRegisteredPowerSettingCallbacks", GetPowerCallbackItemFunctionOffset(), 0, 0 } },
        { "kdppower", { "", "nt!KdpPowerListHead", le_size, 0, 0 } },
        { "callbackdir", {} },
        { "shutdown", { "", "nt!IopNotifyShutdownQueueHead", 0, 0, 0 } },
        { "shutdownlast", { "", "nt!IopNotifyLastChanceShutdownQueueHead", 0, 0, 0 } },
        { "drvreinit", { "", "nt!IopDriverReinitializeQueueHead", le_size + m_PtrSize, 0, 0 } },
        { "bootdrvreinit", { "", "nt!IopBootDriverReinitializeQueueHead", le_size + m_PtrSize, 0, 0 } },
        { "fschange", { "", "nt!IopFsNotifyChangeQueueHead", le_size + m_PtrSize, 0, 0 } },
        { "nmi", { "", "nt!KiNmiCallbackListHead", m_PtrSize, 0, 0 } },
        { "logonsessionroutine", { "", "nt!SeFileSystemNotifyRoutinesHead", m_PtrSize, 0, 0 } },
        { "prioritycallback", { "nt!IopUpdatePriorityCallbackRoutineCount", "nt!IopUpdatePriorityCallbackRoutine", 0,
          0, 0 } },
        { "pnp", {} },
        { "lego", { "", "nt!PspLegoNotifyRoutine", 0, 0, 0 } },
        { "debugprint", { "", "nt!RtlpDebugPrintCallbackList", le_size, 0, 0 } },
        { "alpcplog", { "", "nt!AlpcpLogCallbackListHead", le_size, 0, 0 } },
        { "empcb", { "", "nt!EmpCallbackListHead", GetTypeSize("nt!_GUID"), 0, 0 } },
        { "ioperf", { "", "nt!IopPerfIoTrackingListHead", le_size, 0, 0 } },
        { "dbgklkmd", { "", "nt!DbgkLkmdCallbackArray", 0, 0, 0 } },
        { "ioptimer", { "", "nt!IopTimerQueueHead", timer_routine_offset, 0, 0 } } } };

    for ( auto &cb_pair : m_system_cb_commands ) {
        uint64_t offset_count = 0ULL;
        uint64_t offset_head = 0ULL;

        if ( !cb_pair.second.list_count_name.empty() ) {
            if ( m_sym_cache->GetSymbolOffset(cb_pair.second.list_count_name, true, &offset_count) )
                cb_pair.second.list_count_address = offset_count;
        }

        if ( !cb_pair.second.list_head_name.empty() ) {
            if ( m_sym_cache->GetSymbolOffset(cb_pair.second.list_head_name, true, &offset_head) )
                cb_pair.second.list_head_address = offset_head;
        }
    }
}

void WDbgArk::WalkAnyListWithOffsetToRoutine(const std::string &list_head_name,
                                             const uint64_t offset_list_head,
                                             const uint32_t link_offset,
                                             const bool is_double,
                                             const uint32_t offset_to_routine,
                                             const std::string &type,
                                             const std::string &ext_info,
                                             walkresType* output_list) {
    uint64_t list_head_offset_out = 0;
    uint64_t offset = offset_list_head;

    if ( !offset_to_routine ) {
        err << wa::showminus << __FUNCTION__ << ": invalid parameter" << endlerr;
        return;
    }

    if ( !offset ) {
        if ( !m_sym_cache->GetSymbolOffset(list_head_name, true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
            return;
        } else {
            list_head_offset_out = offset;
        }
    }

    try {
        ExtRemoteList list_head(offset, link_offset, is_double);

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
            uint64_t node = list_head.GetNodeOffset();
            ExtRemoteData structure_data(node + offset_to_routine, m_PtrSize);

            uint64_t routine = structure_data.GetPtr();

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
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkAnyListWithOffsetToObjectPointer(const std::string &list_head_name,
                                                   const uint64_t offset_list_head,
                                                   const bool is_double,
                                                   const uint32_t offset_to_object_pointer,
                                                   void* context,
                                                   RemoteDataCallback callback) {
    uint64_t offset = offset_list_head;

    if ( !offset_to_object_pointer ) {
        err << wa::showminus << __FUNCTION__ << ": invalid parameter offset_to_object_pointer" << endlerr;
        return;
    }

    if ( !offset && !m_sym_cache->GetSymbolOffset(list_head_name, true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
        return;
    }

    try {
        ExtRemoteList list_head(offset, 0, is_double);

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
            ExtRemoteData object_pointer(list_head.GetNodeOffset() + offset_to_object_pointer, m_PtrSize);

            if ( !SUCCEEDED(callback(this, object_pointer, context)) ) {
                err << wa::showminus << __FUNCTION__ << ": error while invoking callback" << endlerr;
                return;
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkDirectoryObject(const uint64_t directory_address,
                                  void* context,
                                  RemoteTypedCallback callback) {
    if ( !directory_address ) {
        err << wa::showminus << __FUNCTION__ << ": invalid directory address" << endlerr;
        return;
    }

    if ( !callback ) {
        err << wa::showminus << __FUNCTION__ << ": invalid callback address" << endlerr;
        return;
    }

    try {
        ExtRemoteTyped directory_object("nt!_OBJECT_DIRECTORY", directory_address, false, NULL, NULL);
        ExtRemoteTyped buckets = directory_object.Field("HashBuckets");

        int64_t num_buckets = buckets.GetTypeSize() / m_PtrSize;

        for ( int64_t i = 0; i < num_buckets; i++ ) {
            for ( ExtRemoteTyped directory_entry = *buckets[i];
                  directory_entry.m_Offset;
                  directory_entry = *directory_entry.Field("ChainLink") ) {
                ExtRemoteTyped object = *directory_entry.Field("Object");

                if ( !SUCCEEDED(callback(this, object, context)) ) {
                    err << wa::showminus << __FUNCTION__ << ": error while invoking callback" << endlerr;
                    return;
                }
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkDeviceNode(const uint64_t device_node_address,
                             void* context,
                             RemoteTypedCallback callback) {
    uint64_t offset = device_node_address;

    if ( !callback ) {
        err << wa::showminus << __FUNCTION__ << ": invalid callback address" << endlerr;
        return;
    }

    try {
        if ( !offset ) {
            if ( !m_sym_cache->GetSymbolOffset("nt!IopRootDeviceNode", true, &offset) ) {
                err << wa::showminus << __FUNCTION__ << ": failed to get nt!IopRootDeviceNode" << endlerr;
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
                err << wa::showminus << __FUNCTION__ << ": error while invoking callback" << endlerr;
                return;
            }

            WalkDeviceNode(child_node.m_Offset, context, callback);
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkAnyTable(const uint64_t table_start,
                           const uint32_t offset_table_skip_start,
                           const uint32_t table_count,
                           const std::string &type,
                           walkresType* output_list,
                           bool break_on_null,
                           bool collect_null) {
    uint64_t offset = table_start + offset_table_skip_start;

    try {
        for ( uint32_t i = 0; i < table_count; i++ ) {
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
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::AddSymbolPointer(const std::string &symbol_name,
                               const std::string &type,
                               const std::string &additional_info,
                               walkresType* output_list) {
    uint64_t offset = 0;

    try {
        if ( m_sym_cache->GetSymbolOffset(symbol_name, true, &offset) ) {
            uint64_t symbol_offset = offset;

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
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

}   // namespace wa
