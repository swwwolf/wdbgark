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

#include <string>
#include <algorithm>
#include <memory>

#include "wdbgark.hpp"
#include "manipulators.hpp"

EXT_DECLARE_GLOBALS();

bool WDbgArk::Init() {
    if ( IsInited() )
        return true;

    CheckSymbolsPath();

    m_obj_helper = std::unique_ptr<WDbgArkObjHelper>(new WDbgArkObjHelper);
    m_color_hack = std::unique_ptr<WDbgArkColorHack>(new WDbgArkColorHack);

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

    if ( !SUCCEEDED( result ) )
        warn << __FUNCTION__ ": GetSystemVersion failed with result = " << result << endlwarn;

    m_is_cur_machine64 = IsCurMachine64();

    InitCallbackCommands();
    InitCalloutNames();
    InitGDTSelectors();

    m_inited = true;

    return m_inited;
}

void WDbgArk::InitCallbackCommands(void) {
    // TODO(swwwolf): optimize by calculating offsets in constructor only once
    // init systemcb map
    SystemCbCommand command_info = { "nt!PspLoadImageNotifyRoutineCount", "nt!PspLoadImageNotifyRoutine", 0 };
    system_cb_commands["image"] = command_info;

    command_info.list_count_name = "nt!PspCreateProcessNotifyRoutineCount";
    command_info.list_head_name = "nt!PspCreateProcessNotifyRoutine";
    system_cb_commands["process"] = command_info;

    command_info.list_count_name = "nt!PspCreateThreadNotifyRoutineCount";
    command_info.list_head_name = "nt!PspCreateThreadNotifyRoutine";
    system_cb_commands["thread"] = command_info;

    command_info.list_count_name = "nt!CmpCallBackCount";
    command_info.list_head_name = "nt!CmpCallBackVector";
    command_info.offset_to_routine = GetCmCallbackItemFunctionOffset();
    system_cb_commands["registry"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!KeBugCheckCallbackListHead";
    command_info.offset_to_routine = GetTypeSize("nt!_LIST_ENTRY");
    system_cb_commands["bugcheck"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!KeBugCheckReasonCallbackListHead";
    command_info.offset_to_routine = GetTypeSize("nt!_LIST_ENTRY");
    system_cb_commands["bugcheckreason"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!PopRegisteredPowerSettingCallbacks";
    command_info.offset_to_routine = GetPowerCallbackItemFunctionOffset();
    system_cb_commands["powersetting"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "";
    command_info.offset_to_routine = 0;
    system_cb_commands["callbackdir"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!IopNotifyShutdownQueueHead";
    system_cb_commands["shutdown"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!IopNotifyLastChanceShutdownQueueHead";
    system_cb_commands["shutdownlast"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!IopDriverReinitializeQueueHead";
    command_info.offset_to_routine = GetTypeSize("nt!_LIST_ENTRY") + m_PtrSize;
    system_cb_commands["drvreinit"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!IopBootDriverReinitializeQueueHead";
    command_info.offset_to_routine = GetTypeSize("nt!_LIST_ENTRY") + m_PtrSize;
    system_cb_commands["bootdrvreinit"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!IopFsNotifyChangeQueueHead";
    command_info.offset_to_routine = GetTypeSize("nt!_LIST_ENTRY") + m_PtrSize;
    system_cb_commands["fschange"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!KiNmiCallbackListHead";
    command_info.offset_to_routine = m_PtrSize;
    system_cb_commands["nmi"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!SeFileSystemNotifyRoutinesHead";
    command_info.offset_to_routine = m_PtrSize;
    system_cb_commands["logonsessionroutine"] = command_info;

    command_info.list_count_name = "nt!IopUpdatePriorityCallbackRoutineCount";
    command_info.list_head_name = "nt!IopUpdatePriorityCallbackRoutine";
    command_info.offset_to_routine = 0;
    system_cb_commands["prioritycallback"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "";
    system_cb_commands["pnp"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!PspLegoNotifyRoutine";    // actually just a pointer
    system_cb_commands["lego"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!RtlpDebugPrintCallbackList";
    command_info.offset_to_routine = GetTypeSize("nt!_LIST_ENTRY");
    system_cb_commands["debugprint"] = command_info;
}

void WDbgArk::InitCalloutNames(void) {
    if ( m_minor_build < W8RTM_VER ) {
        callout_names.push_back("nt!PspW32ProcessCallout");
        callout_names.push_back("nt!PspW32ThreadCallout");
        callout_names.push_back("nt!ExGlobalAtomTableCallout");
        callout_names.push_back("nt!KeGdiFlushUserBatch");
        callout_names.push_back("nt!PopEventCallout");
        callout_names.push_back("nt!PopStateCallout");
        callout_names.push_back("nt!PspW32JobCallout");
        callout_names.push_back("nt!ExDesktopOpenProcedureCallout");
        callout_names.push_back("nt!ExDesktopOkToCloseProcedureCallout");
        callout_names.push_back("nt!ExDesktopCloseProcedureCallout");
        callout_names.push_back("nt!ExDesktopDeleteProcedureCallout");
        callout_names.push_back("nt!ExWindowStationOkToCloseProcedureCallout");
        callout_names.push_back("nt!ExWindowStationCloseProcedureCallout");
        callout_names.push_back("nt!ExWindowStationDeleteProcedureCallout");
        callout_names.push_back("nt!ExWindowStationParseProcedureCallout");
        callout_names.push_back("nt!ExWindowStationOpenProcedureCallout");
        callout_names.push_back("nt!IopWin32DataCollectionProcedureCallout");
        callout_names.push_back("nt!PopWin32InfoCallout");
    }
}

void WDbgArk::InitGDTSelectors(void) {
    if ( m_is_cur_machine64 ) {
        gdt_selectors.push_back(KGDT64_NULL);
        gdt_selectors.push_back(KGDT64_R0_CODE);
        gdt_selectors.push_back(KGDT64_R0_DATA);
        gdt_selectors.push_back(KGDT64_R3_CMCODE);
        gdt_selectors.push_back(KGDT64_R3_DATA);
        gdt_selectors.push_back(KGDT64_R3_CODE);
        gdt_selectors.push_back(KGDT64_SYS_TSS);
        gdt_selectors.push_back(KGDT64_R3_CMTEB);
    } else {
        gdt_selectors.push_back(KGDT_R0_CODE);
        gdt_selectors.push_back(KGDT_R0_DATA);
        gdt_selectors.push_back(KGDT_R3_CODE);
        gdt_selectors.push_back(KGDT_R3_DATA);
        gdt_selectors.push_back(KGDT_TSS);
        gdt_selectors.push_back(KGDT_R0_PCR);
        gdt_selectors.push_back(KGDT_R3_TEB);
        gdt_selectors.push_back(KGDT_LDT);
        gdt_selectors.push_back(KGDT_DF_TSS);
        gdt_selectors.push_back(KGDT_NMI_TSS);
        gdt_selectors.push_back(KGDT_GDT_ALIAS);
        gdt_selectors.push_back(KGDT_CDA16);
        gdt_selectors.push_back(KGDT_CODE16);
        gdt_selectors.push_back(KGDT_STACK16);
    }
}

void WDbgArk::CheckSymbolsPath(void) {
    unsigned __int32 buffer_size = 0;
    HRESULT result = m_Symbols->GetSymbolPath(nullptr, 0, reinterpret_cast<PULONG>(&buffer_size));

    if ( SUCCEEDED(result) && buffer_size ) {
        std::unique_ptr<char[]> symbol_path_buffer(new char[buffer_size]);

        if ( symbol_path_buffer ) {
            result = m_Symbols->GetSymbolPath(symbol_path_buffer.get(),
                                              buffer_size,
                                              reinterpret_cast<PULONG>(&buffer_size));

            if ( SUCCEEDED(result) ) {
                std::string check_path = symbol_path_buffer.get();

                if ( check_path.empty() ) {
                    warn << __FUNCTION__ << ": seems that your symbol path is empty. Be sure to fix it!" << endlwarn;
                } else if ( check_path.find(MS_PUBLIC_SYMBOLS_SERVER) == std::string::npos ) {
                    warn << __FUNCTION__ << ": seems that your symbol path may be incorrect. ";
                    warn << "Be sure to include Microsoft Symbol Server (" << MS_PUBLIC_SYMBOLS_SERVER << ")" << endlwarn;
                }
            } else {
                warn << __FUNCTION__ ": GetSymbolPath failed" << endlwarn;
            }
        }
    } else {
        warn << __FUNCTION__ ": GetSymbolPath failed" << endlwarn;
    }
}

void WDbgArk::WalkAnyListWithOffsetToRoutine(const std::string &list_head_name,
                                             const unsigned __int64 offset_list_head,
                                             const unsigned __int32 link_offset,
                                             const bool is_double,
                                             const unsigned __int32 offset_to_routine,
                                             const std::string &type,
                                             const std::string &ext_info,
                                             walkresType &output_list) {
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

                info.routine_address = routine;
                info.type = type;
                info.info = ext_info;
                info.list_head_name = list_head_name;
                info.object_offset = node;
                info.list_head_offset = list_head_offset_out;

                output_list.push_back(info);
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

void WDbgArk::AddSymbolPointer(const std::string &symbol_name,
                               const std::string &type,
                               const std::string &additional_info,
                               walkresType &output_list) {
    unsigned __int64 offset = 0;

    try {
        if ( GetSymbolOffset(symbol_name.c_str(), true, &offset) ) {
            unsigned __int64 symbol_offset = offset;

            ExtRemoteData routine_ptr(offset, m_PtrSize);
            offset = routine_ptr.GetPtr();

            if ( offset ) {
                OutputWalkInfo info;

                info.routine_address = offset;
                info.type = type;
                info.info = additional_info;
                info.list_head_name = symbol_name;
                info.object_offset = 0ULL;
                info.list_head_offset = symbol_offset;

                output_list.push_back(info);
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}
