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

// TODO(swwwolf): DbgkLkmdRegisterCallback (WINDOWS 7+), ObRegisterCallbacks, CrashdmpCallTable,
//                KdRegisterPowerHandler, IoRegisterIoTracking

/*

"!systemcb /type type_name"

Type names are:

image
process
thread
registry
bugcheck
bugcheckreason
bugcheckaddpages
powersetting
callbackdir
shutdown
shutdownlast
drvreinit
bootdrvreinit
fschange
nmi
logonsessionroutine
prioritycallback
pnp
lego
debugprint
alpcplog
empcb
ioperf
dbgklkmd

Default: all of them

*/

/*

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF        RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID                 Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _EX_CALLBACK {
    EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

*/

/*

BUGCHECK & BUGCHECKREASON:

typedef struct _KBUGCHECK_CALLBACK_RECORD {
    LIST_ENTRY Entry;
    PKBUGCHECK_CALLBACK_ROUTINE CallbackRoutine;
    __field_bcount_opt(Length) PVOID Buffer;
    ULONG Length;
    PUCHAR Component;
    ULONG_PTR Checksum;
    UCHAR State;
} KBUGCHECK_CALLBACK_RECORD, *PKBUGCHECK_CALLBACK_RECORD;

typedef struct _KBUGCHECK_REASON_CALLBACK_RECORD {
    LIST_ENTRY Entry;
    PKBUGCHECK_REASON_CALLBACK_ROUTINE CallbackRoutine;
    PUCHAR Component;
    ULONG_PTR Checksum;
    KBUGCHECK_CALLBACK_REASON Reason;
    UCHAR State;
} KBUGCHECK_REASON_CALLBACK_RECORD, *PKBUGCHECK_REASON_CALLBACK_RECORD;

*/

/*

CALLBACKDIR:

typedef struct _CALLBACK_OBJECT {
    ULONG               Signature;
    KSPIN_LOCK          Lock;
    LIST_ENTRY          RegisteredCallbacks;
    BOOLEAN             AllowMultipleCallbacks;
    UCHAR               reserved[3];
} CALLBACK_OBJECT , *PCALLBACK_OBJECT;

//
// Executive callback registration structure definition.
//

typedef struct _CALLBACK_REGISTRATION {
    LIST_ENTRY          Link;
    PCALLBACK_OBJECT    CallbackObject;
    PCALLBACK_FUNCTION  CallbackFunction;
    PVOID               CallbackContext;
    ULONG               Busy;
    BOOLEAN             UnregisterWaiting;
} CALLBACK_REGISTRATION , *PCALLBACK_REGISTRATION;

*/

/*

SHUTDOWN & SHUTDOWNLAST:

typedef struct _SHUTDOWN_PACKET {
    LIST_ENTRY ListEntry;
    PDEVICE_OBJECT DeviceObject;
} SHUTDOWN_PACKET, *PSHUTDOWN_PACKET;

*/

/*

FSCHANGE:

typedef struct _NOTIFICATION_PACKET {
    LIST_ENTRY ListEntry;
    PDRIVER_OBJECT DriverObject;
    PDRIVER_FS_NOTIFICATION NotificationRoutine;
} NOTIFICATION_PACKET, *PNOTIFICATION_PACKET;


*/

/*

LOGONSESSIONROUTINES:

typedef struct _SEP_LOGON_SESSION_TERMINATED_NOTIFICATION {
    struct _SEP_LOGON_SESSION_TERMINATED_NOTIFICATION *Next;
    PSE_LOGON_SESSION_TERMINATED_ROUTINE CallbackRoutine;
} SEP_LOGON_SESSION_TERMINATED_NOTIFICATION, *PSEP_LOGON_SESSION_TERMINATED_NOTIFICATION;

*/

/*

PNP:

x86 offset to routine is 0x14
x64 offset to routine is 0x20

XP/W2K3:

//
IopProfileNotifyList
//

//
InsertTailList(&deviceNode->TargetDeviceNotify, (PLIST_ENTRY)entry);
//

//
#define NOTIFY_DEVICE_CLASS_HASH_BUCKETS 13
LIST_ENTRY IopDeviceClassNotifyList[NOTIFY_DEVICE_CLASS_HASH_BUCKETS];
InsertTailList( (PLIST_ENTRY) &(IopDeviceClassNotifyList[ IopHashGuid(&(entry->ClassGuid)) ]), (PLIST_ENTRY) entry);
//

VISTA+:

IopProfileNotifyList and IopDeviceClassNotifyList were replaced by PnpProfileNotifyList and PnpDeviceClassNotifyList

*/

#include <map>
#include <string>
#include <utility>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"

EXT_COMMAND(wa_systemcb,
            "Output kernel-mode registered callback(s)",
            "{type;s;o;type,Callback type name:\n"\
            "image, process, thread, registry, bugcheck, bugcheckreason, bugcheckaddpages, powersetting, callbackdir, "\
            "shutdown, shutdownlast, drvreinit, bootdrvreinit, fschange, nmi, logonsessionroutine, prioritycallback, "\
            "pnp, lego, debugprint, alpcplog, empcb, ioperf, dbgklkmd}") {
    std::string type;
    walkresType output_list;

    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( HasArg("type") )   // callback type was provided
        type.assign(GetArgStr("type"));

    out << "Displaying OS registered callback(s) " << type << endlout;

    std::unique_ptr<WDbgArkAnalyze> display(new WDbgArkAnalyze(WDbgArkAnalyze::AnalyzeTypeCallback));
    display->PrintFooter();

    try {
        if ( type.empty() ) {
            for ( callbacksInfo::const_iterator citer = m_system_cb_commands.cbegin();
                  citer != m_system_cb_commands.cend();
                  ++citer ) {
                CallCorrespondingWalkListRoutine(citer, output_list);
            }
        } else {
            callbacksInfo::const_iterator citer = m_system_cb_commands.find(type);

            if ( citer != m_system_cb_commands.end() )
                CallCorrespondingWalkListRoutine(citer, output_list);
            else
                err << __FUNCTION__ << ": invalid type was specified" << endlerr;
        }

        std::string prev_list_head;

        for ( const OutputWalkInfo &walk_info : output_list ) {
            if ( prev_list_head != walk_info.list_head_name ) {
                out << walk_info.list_head_name;

                if ( walk_info.list_head_offset )
                    out << ": " << std::hex << std::showbase << walk_info.list_head_offset;

                out << endlout;
                display->PrintHeader();
            }

            display->AnalyzeAddressAsRoutine(walk_info.routine_address, walk_info.type, walk_info.info);
            display->PrintFooter();

            prev_list_head = walk_info.list_head_name;
        }

        display->PrintFooter();
        output_list.clear();
    }
    catch( const ExtInterruptException& ) {
        throw;
    }
}

void WDbgArk::CallCorrespondingWalkListRoutine(const callbacksInfo::const_iterator &citer,
                                               walkresType &output_list) {
    if ( citer->first == "registry" ) {
        if ( m_minor_build == WXP_VER || m_minor_build == W2K3_VER ) {
            WalkExCallbackList(citer->second.list_count_name,
                               0ULL,
                               0,
                               citer->second.list_head_name,
                               0ULL,
                               m_PtrSize,
                               citer->first,
                               output_list);
        } else {
            WalkAnyListWithOffsetToRoutine("nt!CallbackListHead",
                                           0ULL,
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first,
                                           "",
                                           output_list);
        }
    } else if ( citer->first == "image" || citer->first == "process" || citer->first == "thread" ) {
        WalkExCallbackList(citer->second.list_count_name,
                           0ULL,
                           0,
                           citer->second.list_head_name,
                           0ULL,
                           m_PtrSize,
                           citer->first,
                           output_list);
    } else if ( citer->first == "bugcheck" || citer->first == "bugcheckreason" ||
              (citer->first == "bugcheckaddpages" && m_minor_build >= VISTA_SP1_VER) ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "powersetting" && m_minor_build > W2K3_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "callbackdir" ) {
        WalkCallbackDirectory(citer->first, output_list);
    } else if ( citer->first == "shutdown" || citer->first == "shutdownlast" ) {
        WalkShutdownList(citer->second.list_head_name, citer->first, output_list);
    } else if ( citer->first == "drvreinit" || citer->first == "bootdrvreinit" ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "fschange" ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "nmi" && m_minor_build > WXP_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "logonsessionroutine" ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "prioritycallback" && m_minor_build >= W7RTM_VER ) {
        WalkExCallbackList(citer->second.list_count_name,
                           0ULL,
                           0,
                           citer->second.list_head_name,
                           0ULL,
                           m_PtrSize,
                           citer->first,
                           output_list);
    } else if ( citer->first == "pnp" ) {
        WalkPnpLists(citer->first, output_list);
    } else if ( citer->first == "lego" ) {
        AddSymbolPointer(citer->second.list_head_name, citer->first, "", output_list);
    } else if ( citer->first == "debugprint" && m_minor_build >= VISTA_RTM_VER ) {
        if ( m_minor_build == VISTA_RTM_VER ) {
            AddSymbolPointer("nt!RtlpDebugPrintCallback", citer->first, "", output_list);
        } else {
            WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                           0ULL,
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first,
                                           "",
                                           output_list);
        }
    } else if ( citer->first == "alpcplog" && m_minor_build >= VISTA_RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "empcb" && m_minor_build >= VISTA_RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       GetEmpCallbackItemLinkOffset(),
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "ioperf" && m_minor_build >= W8RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0ULL,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "dbgklkmd" && m_minor_build >= W7RTM_VER ) {
        WalkExCallbackList("",
                           0ULL,
                           GetDbgkLkmdCallbackCount(),
                           citer->second.list_head_name,
                           0ULL,
                           GetDbgkLkmdCallbackArrayDistance(),
                           "dbgklkmd",
                           output_list);
    }
}

void WDbgArk::WalkExCallbackList(const std::string &list_count_name,
                                 const unsigned __int64 offset_list_count,
                                 const unsigned __int32 count,
                                 const std::string &list_head_name,
                                 const unsigned __int64 offset_list_head,
                                 const unsigned __int32 array_distance,
                                 const std::string &type,
                                 walkresType &output_list) {
    unsigned __int64 offset = offset_list_count;
    unsigned __int32 rcount = count;
    ExtRemoteData    routine_count;

    try {
        if ( !rcount && !offset && !GetSymbolOffset(list_count_name.c_str(), true, &offset) ) {
            err << __FUNCTION__ << ": failed to get " << list_count_name << endlerr;
            return;
        }

        if ( !rcount )
            routine_count.Set(offset, static_cast<unsigned __int32>(sizeof(unsigned __int32)));

        offset = offset_list_head;

        if ( !offset && !GetSymbolOffset(list_head_name.c_str(), true, &offset) ) {
            err << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
            return;
        }

        const unsigned __int64 list_head_offset_out = offset;

        if ( !rcount )
            rcount = routine_count.GetUlong();

        for ( unsigned __int32 i = 0; i < rcount; i++ ) {
            ExtRemoteData notify_routine_list(offset + i * array_distance, m_PtrSize);

            const unsigned __int64 ex_callback_fast_ref = notify_routine_list.GetPtr();

            if ( ex_callback_fast_ref ) {
                ExtRemoteData routine_block(
                    m_obj_helper->ExFastRefGetObject(ex_callback_fast_ref) + GetTypeSize("nt!_EX_RUNDOWN_REF"),
                    m_PtrSize);

                const unsigned __int64 notify_routine = routine_block.GetPtr();

                if ( notify_routine ) {
                    OutputWalkInfo info;

                    info.routine_address = notify_routine;
                    info.type = type;
                    info.info = "";
                    info.list_head_name = list_head_name;
                    info.object_offset = 0ULL;
                    info.list_head_offset = list_head_offset_out;

                    output_list.push_back(info);
                }
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

//
// http://redplait.blogspot.ru/2010/08/cmregistercallbackex-on-vista.html
//
unsigned __int32 WDbgArk::GetCmCallbackItemFunctionOffset() const {
    if ( !m_is_cur_machine64 )
        return 0x1C;

    if ( m_minor_build >= VISTA_RTM_VER && m_minor_build < W7RTM_VER )
        return 0x30;
    else if ( m_minor_build >= W7RTM_VER )
        return 0x28;

    return 0;
}

//
// http://redplait.blogspot.ru/2012/10/poregisterpowersettingcallback-callbacks.html
//
unsigned __int32 WDbgArk::GetPowerCallbackItemFunctionOffset() const {
    if ( !m_is_cur_machine64 )
        return 0x28;

    return 0x40;
}

unsigned __int32 WDbgArk::GetPnpCallbackItemFunctionOffset() const {
    if ( !m_is_cur_machine64 )
        return 0x14;

    return 0x20;
}

//
// http://redplait.blogspot.ru/2012/09/emproviderregisterempproviderregister.html
//
unsigned __int32 WDbgArk::GetEmpCallbackItemLinkOffset() const {
    if ( !m_is_cur_machine64 )
        return 0x1C;

    return 0x28;
}

void WDbgArk::WalkCallbackDirectory(const std::string &type, walkresType &output_list) {
    WalkCallbackContext context;

    context.type = type;
    context.output_list_pointer = &output_list;

    WalkDirectoryObject(m_obj_helper->FindObjectByName("Callback", 0ULL),
                        reinterpret_cast<void*>(&context),
                        DirectoryObjectCallback);
}

HRESULT WDbgArk::DirectoryObjectCallback(WDbgArk* wdbg_ark_class, const ExtRemoteTyped &object, void* context) {
    WalkCallbackContext* cb_context     = reinterpret_cast<WalkCallbackContext*>(context);
    std::string          type           = cb_context->type;
    std::string          list_head_name = "\\Callback\\";

    std::pair<HRESULT, std::string> result = wdbg_ark_class->m_obj_helper->GetObjectName(object);

    if ( !SUCCEEDED(result.first) ) {
        std::stringstream tmpwarn;
        tmpwarn << __FUNCTION__ << ": failed to get object name" << endlwarn;
    } else {
        list_head_name.append(result.second);
    }

    // Signature + Lock
    const unsigned __int64 offset_list_head = object.m_Offset + g_Ext->m_PtrSize + g_Ext->m_PtrSize;

    // Link + CallbackObject
    const unsigned __int32 offset_to_routine = GetTypeSize("nt!_LIST_ENTRY") + g_Ext->m_PtrSize;

    wdbg_ark_class->WalkAnyListWithOffsetToRoutine(list_head_name,
                                                   offset_list_head,
                                                   0,
                                                   true,
                                                   offset_to_routine,
                                                   type,
                                                   "",
                                                   *cb_context->output_list_pointer);

    return S_OK;
}

void WDbgArk::WalkShutdownList(const std::string &list_head_name, const std::string &type, walkresType &output_list) {
    WalkCallbackContext context;

    context.type = type;
    context.list_head_name = list_head_name;
    context.output_list_pointer = &output_list;

    if ( !GetSymbolOffset( list_head_name.c_str(), true, &context.list_head_offset ) )
        warn << __FUNCTION__ << ": GetSymbolOffset failed with " << list_head_name << endlwarn;

    WalkAnyListWithOffsetToObjectPointer(list_head_name,
                                         0ULL,
                                         true,
                                         GetTypeSize("nt!_LIST_ENTRY"),
                                         reinterpret_cast<void*>(&context),
                                         ShutdownListCallback);
}

HRESULT WDbgArk::ShutdownListCallback(WDbgArk* wdbg_ark_class, ExtRemoteData &object_pointer, void* context) {
    WalkCallbackContext* cb_context = reinterpret_cast<WalkCallbackContext*>(context);
    std::string          type       = cb_context->type;

    try {
        ExtRemoteTyped device_object("nt!_DEVICE_OBJECT", object_pointer.GetPtr(), false, NULL, NULL);
        ExtRemoteTyped driver_object_ptr = device_object.Field("DriverObject");
        ExtRemoteTyped driver_object = *driver_object_ptr;
        ExtRemoteTyped major_functions = driver_object.Field("MajorFunction");

        std::stringstream info;

        info << "<exec cmd=\"!devobj " << std::hex << std::showbase << object_pointer.GetPtr();
        info << "\">!devobj" << "</exec>" << " ";

        info << "<exec cmd=\"!devstack " << std::hex << std::showbase << object_pointer.GetPtr();
        info << "\">!devstack" << "</exec>" << " ";

        info << "<exec cmd=\"!drvobj " << std::hex << std::showbase << driver_object.m_Offset;
        info << " 7" << "\">!drvobj" << "</exec>";

        const unsigned __int64 routine_address = major_functions[static_cast<ULONG>(IRP_MJ_SHUTDOWN)].GetPtr();

        OutputWalkInfo winfo;

        winfo.routine_address = routine_address;
        winfo.type = type;
        winfo.info = info.str();
        winfo.list_head_name = cb_context->list_head_name;
        winfo.object_offset = 0ULL;
        winfo.list_head_offset = cb_context->list_head_offset;

        cb_context->output_list_pointer->push_back(winfo);
    }
    catch ( const ExtRemoteException &Ex ) {
        std::stringstream tmperr;
        tmperr << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;

        return Ex.GetStatus();
    }

    return S_OK;
}

// IopProfileNotifyList and IopDeviceClassNotifyList were replaced
// by PnpProfileNotifyList and PnpDeviceClassNotifyList in Vista+
void WDbgArk::WalkPnpLists(const std::string &type, walkresType &output_list) {
    std::string            list_head_name;
    unsigned __int64       offset            = 0;
    const unsigned __int32 offset_to_routine = GetPnpCallbackItemFunctionOffset();

    if ( m_minor_build == WXP_VER || m_minor_build == W2K3_VER )
        list_head_name = "nt!IopProfileNotifyList";
    else
        list_head_name = "nt!PnpProfileNotifyList";

    WalkAnyListWithOffsetToRoutine(list_head_name, 0ULL, 0, true, offset_to_routine, type, "", output_list);

    if ( m_minor_build == WXP_VER || m_minor_build == W2K3_VER )
        list_head_name = "nt!IopDeviceClassNotifyList";
    else
        list_head_name = "nt!PnpDeviceClassNotifyList";

    if ( !GetSymbolOffset(list_head_name.c_str(), true, &offset) ) {
        err << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
    } else {
        for ( int i = 0; i < NOTIFY_DEVICE_CLASS_HASH_BUCKETS; i++ ) {
            WalkAnyListWithOffsetToRoutine(list_head_name,
                                           offset + i * GetTypeSize("nt!_LIST_ENTRY"),
                                           0,
                                           true,
                                           offset_to_routine,
                                           type,
                                           "",
                                           output_list);
        }
    }

    WalkCallbackContext context;

    context.type = type;
    context.list_head_name = "nt!IopRootDeviceNode";
    context.output_list_pointer = &output_list;

    WalkDeviceNode(0ULL, reinterpret_cast<void*>(&context), DeviceNodeCallback);
}

HRESULT WDbgArk::DeviceNodeCallback(WDbgArk* wdbg_ark_class, ExtRemoteTyped &device_node, void* context) {
    WalkCallbackContext* cb_context = reinterpret_cast<WalkCallbackContext*>(context);

    std::stringstream info;

    info << std::setw(37) << "<exec cmd=\"!devnode " << std::hex << std::showbase << device_node.m_Offset;
    info << "\">!devnode" << "</exec>";

    wdbg_ark_class->WalkAnyListWithOffsetToRoutine(cb_context->list_head_name,
                                                   device_node.Field("TargetDeviceNotify").m_Offset,
                                                   0,
                                                   true,
                                                   wdbg_ark_class->GetPnpCallbackItemFunctionOffset(),
                                                   cb_context->type,
                                                   info.str(),
                                                   *cb_context->output_list_pointer);

    return S_OK;
}
