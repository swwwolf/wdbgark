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

"!systemcb /type type_name"

Type names are:

image
process
thread
registry
bugcheck
bugcheckreason
bugcheckaddpages
bugcheckaddremovepages
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
kdppower
ioptimer

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

/*
IopTimer

NTSTATUS __stdcall IoInitializeTimer(PDEVICE_OBJECT DeviceObject, PIO_TIMER_ROUTINE TimerRoutine, PVOID Context)
{
  _IO_TIMER *IoTimer; // edx@1

  IoTimer = DeviceObject->Timer;

  if ( !IoTimer )
  {
    IoTimer = (_IO_TIMER *)ExAllocatePoolWithTag(0, 0x18u, 'iToI');

    if ( !IoTimer )
      return STATUS_INSUFFICIENT_RESOURCES;

    memset(IoTimer, 0, sizeof(_IO_TIMER));
    IoTimer->Type = 9;
    IoTimer->DeviceObject = DeviceObject;
    DeviceObject->Timer = IoTimer;
  }

  IoTimer->TimerRoutine = TimerRoutine;
  IoTimer->Context = Context;
  ExfInterlockedInsertTailList(&IopTimerQueueHead, &IoTimer->TimerList, &IopTimerLock);

  return 0;
}
*/

#include <map>
#include <string>
#include <utility>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"
#include "systemver.hpp"
#include "systemcb.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
uint32_t GetDbgkLkmdCallbackCount() { return 0x08; }
uint32_t GetDbgkLkmdCallbackArrayDistance() { return 2 * g_Ext->m_PtrSize; }
//////////////////////////////////////////////////////////////////////////
// http://redplait.blogspot.ru/2010/08/cmregistercallbackex-on-vista.html
//////////////////////////////////////////////////////////////////////////
uint32_t GetCmCallbackItemFunctionOffset() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() )
        return 0;

    if ( !g_Ext->IsCurMachine64() )
        return 0x1C;

    if ( system_ver.IsBuildInRangeStrict(VISTA_RTM_VER, VISTA_SP2_VER) )
        return 0x30;
    else if ( system_ver.GetStrictVer() >= W7RTM_VER )
        return 0x28;

    return 0;
}

//////////////////////////////////////////////////////////////////////////
// http://redplait.blogspot.ru/2012/10/poregisterpowersettingcallback-callbacks.html
//////////////////////////////////////////////////////////////////////////
uint32_t GetPowerCallbackItemFunctionOffset() {
    if ( !g_Ext->IsCurMachine64() )
        return 0x28;

    return 0x40;
}
//////////////////////////////////////////////////////////////////////////
uint32_t GetPnpCallbackItemFunctionOffset() {
    if ( !g_Ext->IsCurMachine64() )
        return 0x14;

    return 0x20;
}
//////////////////////////////////////////////////////////////////////////
// http://redplait.blogspot.ru/2012/09/emproviderregisterempproviderregister.html
//////////////////////////////////////////////////////////////////////////
uint32_t GetEmpCallbackItemLinkOffset() {
    if ( !g_Ext->IsCurMachine64() )
        return 0x1C;

    return 0x28;
}
//////////////////////////////////////////////////////////////////////////

EXT_COMMAND(wa_systemcb,
            "Output kernel-mode registered callback(s)",
            "{type;s;o;type,Callback type name:\n"\
            "image, process, thread, registry, bugcheck, bugcheckreason, bugcheckaddpages, bugcheckaddremovepages, "\
            "powersetting, callbackdir, "\
            "shutdown, shutdownlast, drvreinit, bootdrvreinit, fschange, nmi, logonsessionroutine, prioritycallback, "\
            "pnp, lego, debugprint, alpcplog, empcb, ioperf, dbgklkmd, kdppower, ioptimer}") {
    std::string type = "*";
    walkresType output_list;

    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( HasArg("type") )   // callback type was provided
        type.assign(GetArgStr("type"));

    out << wa::showplus << "Displaying OS registered callback(s) with type " << type << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeCallback);

    try {
        if ( type == "*" ) {
            for ( auto citer = m_system_cb_commands.cbegin(); citer != m_system_cb_commands.cend(); ++citer ) {
                out << wa::showplus << "Collecting " << citer->first << " callbacks" << endlout;
                CallCorrespondingWalkListRoutine(citer, &output_list);
            }
        } else {
            auto citer = m_system_cb_commands.find(type);

            if ( citer != m_system_cb_commands.end() ) {
                out << wa::showplus << "Collecting " << citer->first << " callbacks" << endlout;
                CallCorrespondingWalkListRoutine(citer, &output_list);
            } else {
                err << wa::showminus << __FUNCTION__ << ": invalid type was specified" << endlerr;
            }
        }

        // displaying collected information
        display->PrintFooter();
        std::string prev_list_head;

        for ( const auto &walk_info : output_list ) {
            if ( prev_list_head != walk_info.list_head_name ) {
                out << wa::showplus << walk_info.list_head_name;

                if ( walk_info.list_head_address )
                    out << ": " << std::hex << std::showbase << walk_info.list_head_address;

                out << endlout;
                display->PrintHeader();
            }

            display->Analyze(walk_info.address, walk_info.type, walk_info.info);
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
                                               walkresType* output_list) {
    if ( citer->first == "registry" ) {
        if ( m_system_ver->GetStrictVer() <= W2K3_VER ) {
            WalkExCallbackList(citer->second.list_count_name,
                               citer->second.list_count_address,
                               0,
                               citer->second.list_head_name,
                               citer->second.list_head_address,
                               m_PtrSize,
                               citer->first,
                               output_list);
        } else {
            WalkAnyListWithOffsetToRoutine("nt!CallbackListHead",
                                           citer->second.list_head_address,
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first,
                                           "",
                                           output_list);
        }
    } else if ( citer->first == "image" || citer->first == "process" || citer->first == "thread" ) {
        WalkExCallbackList(citer->second.list_count_name,
                           citer->second.list_count_address,
                           0,
                           citer->second.list_head_name,
                           citer->second.list_head_address,
                           m_PtrSize,
                           citer->first,
                           output_list);
    } else if ( citer->first == "bugcheck" || citer->first == "bugcheckreason" ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "bugcheckaddpages" && m_system_ver->IsBuildInRangeStrict(VISTA_SP1_VER, W81RTM_VER) ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "bugcheckaddremovepages" && m_system_ver->GetStrictVer() >= W10RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "powersetting" && m_system_ver->GetStrictVer() >= VISTA_RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "kdppower" && m_system_ver->GetStrictVer() >= W81RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
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
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "fschange" ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "nmi" && m_system_ver->GetStrictVer() >= W2K3_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "logonsessionroutine" ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "prioritycallback" && m_system_ver->GetStrictVer() >= W7RTM_VER ) {
        WalkExCallbackList(citer->second.list_count_name,
                           citer->second.list_count_address,
                           0,
                           citer->second.list_head_name,
                           citer->second.list_head_address,
                           m_PtrSize,
                           citer->first,
                           output_list);
    } else if ( citer->first == "pnp" ) {
        WalkPnpLists(citer->first, output_list);
    } else if ( citer->first == "lego" ) {
        AddSymbolPointer(citer->second.list_head_name, citer->first, "", output_list);
    } else if ( citer->first == "debugprint" && m_system_ver->GetStrictVer() >= VISTA_RTM_VER ) {
        if ( m_system_ver->GetStrictVer() == VISTA_RTM_VER ) {
            AddSymbolPointer("nt!RtlpDebugPrintCallback", citer->first, "", output_list);
        } else {
            WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                           citer->second.list_head_address,
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first,
                                           "",
                                           output_list);
        }
    } else if ( citer->first == "alpcplog" && m_system_ver->GetStrictVer() >= VISTA_RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "empcb" && m_system_ver->GetStrictVer() >= VISTA_RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       GetEmpCallbackItemLinkOffset(),
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "ioperf" && m_system_ver->GetStrictVer() >= W8RTM_VER ) {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       citer->second.list_head_address,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    } else if ( citer->first == "dbgklkmd" && m_system_ver->GetStrictVer() >= W7RTM_VER ) {
        WalkExCallbackList("",
                           citer->second.list_count_address,
                           GetDbgkLkmdCallbackCount(),
                           citer->second.list_head_name,
                           citer->second.list_head_address,
                           GetDbgkLkmdCallbackArrayDistance(),
                           "dbgklkmd",
                           output_list);
    } else if ( citer->first == "ioptimer" ) {
        uint32_t link_offset = 0;

        if ( GetFieldOffset("nt!_IO_TIMER", "TimerList", reinterpret_cast<PULONG>(&link_offset)) != 0 ) {
            warn << wa::showqmark << __FUNCTION__ << ": GetFieldOffset failed with nt!_IO_TIMER.TimerList" << endlwarn;
        } else {
            WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                           citer->second.list_head_address,
                                           link_offset,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first,
                                           "",
                                           output_list);
        }
    }
}

void WDbgArk::WalkExCallbackList(const std::string &list_count_name,
                                 const uint64_t offset_list_count,
                                 const uint32_t count,
                                 const std::string &list_head_name,
                                 const uint64_t offset_list_head,
                                 const uint32_t array_distance,
                                 const std::string &type,
                                 walkresType* output_list) {
    uint64_t offset = offset_list_count;
    uint32_t rcount = count;
    ExtRemoteData routine_count;

    try {
        if ( !rcount && !offset && !m_sym_cache->GetSymbolOffset(list_count_name, true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get " << list_count_name << endlerr;
            return;
        }

        if ( !rcount )
            routine_count.Set(offset, static_cast<uint32_t>(sizeof(uint32_t)));

        offset = offset_list_head;

        if ( !offset && !m_sym_cache->GetSymbolOffset(list_head_name, true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
            return;
        }

        const uint64_t list_head_offset_out = offset;

        if ( !rcount )
            rcount = routine_count.GetUlong();

        for ( uint32_t i = 0; i < rcount; i++ ) {
            ExtRemoteData notify_routine_list(offset + i * array_distance, m_PtrSize);

            const uint64_t ex_callback_fast_ref = notify_routine_list.GetPtr();

            if ( ex_callback_fast_ref ) {
                ExtRemoteData routine_block(
                    m_obj_helper->ExFastRefGetObject(ex_callback_fast_ref) + GetTypeSize("nt!_EX_RUNDOWN_REF"),
                    m_PtrSize);

                const uint64_t notify_routine = routine_block.GetPtr();

                if ( notify_routine ) {
                    OutputWalkInfo info;

                    info.address = notify_routine;
                    info.type = type;
                    info.info.clear();
                    info.list_head_name = list_head_name;
                    info.object_address = 0ULL;
                    info.list_head_address = list_head_offset_out;

                    output_list->push_back(info);
                }
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void WDbgArk::WalkCallbackDirectory(const std::string &type, walkresType* output_list) {
    WalkCallbackContext context;

    context.type = type;
    context.output_list_pointer = output_list;

    WalkDirectoryObject(m_obj_helper->FindObjectByName("Callback"),
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
        tmpwarn << wa::showqmark << __FUNCTION__ << ": failed to get object name" << endlwarn;
    } else {
        list_head_name.append(result.second);
    }

    // Signature + Lock
    const uint64_t offset_list_head = object.m_Offset + g_Ext->m_PtrSize + g_Ext->m_PtrSize;

    // Link + CallbackObject
    const uint32_t offset_to_routine = GetTypeSize("nt!_LIST_ENTRY") + g_Ext->m_PtrSize;

    wdbg_ark_class->WalkAnyListWithOffsetToRoutine(list_head_name,
                                                   offset_list_head,
                                                   0,
                                                   true,
                                                   offset_to_routine,
                                                   type,
                                                   "",
                                                   cb_context->output_list_pointer);

    return S_OK;
}

void WDbgArk::WalkShutdownList(const std::string &list_head_name, const std::string &type, walkresType* output_list) {
    WalkCallbackContext context;

    context.type = type;
    context.list_head_name = list_head_name;
    context.output_list_pointer = output_list;

    if ( !m_sym_cache->GetSymbolOffset(list_head_name, true, &context.list_head_address) )
        warn << wa::showqmark << __FUNCTION__ << ": GetSymbolOffset failed with " << list_head_name << endlwarn;

    WalkAnyListWithOffsetToObjectPointer(list_head_name,
                                         0ULL,
                                         true,
                                         GetTypeSize("nt!_LIST_ENTRY"),
                                         reinterpret_cast<void*>(&context),
                                         ShutdownListCallback);
}

HRESULT WDbgArk::ShutdownListCallback(WDbgArk*, const ExtRemoteData &object_pointer, void* context) {
    WalkCallbackContext* cb_context = reinterpret_cast<WalkCallbackContext*>(context);
    std::string          type       = cb_context->type;

    try {
        uint64_t object_ptr = const_cast<ExtRemoteData &>(object_pointer).GetPtr();

        ExtRemoteTyped device_object("nt!_DEVICE_OBJECT", object_ptr, false, NULL, NULL);
        ExtRemoteTyped driver_object_ptr = device_object.Field("DriverObject");
        ExtRemoteTyped driver_object = *driver_object_ptr;
        ExtRemoteTyped major_functions = driver_object.Field("MajorFunction");

        std::stringstream info;

        info << "<exec cmd=\"!devobj " << std::hex << std::showbase << object_ptr;
        info << "\">!devobj" << "</exec>" << " ";

        info << "<exec cmd=\"!devstack " << std::hex << std::showbase << object_ptr;
        info << "\">!devstack" << "</exec>" << " ";

        info << "<exec cmd=\"!drvobj " << std::hex << std::showbase << driver_object.m_Offset;
        info << " 7" << "\">!drvobj" << "</exec>";

        const uint64_t routine_address = major_functions[static_cast<ULONG>(IRP_MJ_SHUTDOWN)].GetPtr();

        OutputWalkInfo winfo;

        winfo.address = routine_address;
        winfo.type = type;
        winfo.info = info.str();
        winfo.list_head_name = cb_context->list_head_name;
        winfo.object_address = 0ULL;
        winfo.list_head_address = cb_context->list_head_address;

        cb_context->output_list_pointer->push_back(winfo);
    }
    catch ( const ExtRemoteException &Ex ) {
        std::stringstream tmperr;
        tmperr << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;

        return Ex.GetStatus();
    }

    return S_OK;
}

// IopProfileNotifyList and IopDeviceClassNotifyList were replaced
// by PnpProfileNotifyList and PnpDeviceClassNotifyList in Vista+
void WDbgArk::WalkPnpLists(const std::string &type, walkresType* output_list) {
    std::string list_head_name;
    uint64_t offset = 0;
    const uint32_t offset_to_routine = GetPnpCallbackItemFunctionOffset();

    if ( m_system_ver->GetStrictVer() <= W2K3_VER )
        list_head_name = "nt!IopProfileNotifyList";
    else
        list_head_name = "nt!PnpProfileNotifyList";

    WalkAnyListWithOffsetToRoutine(list_head_name, 0ULL, 0, true, offset_to_routine, type, "", output_list);

    if ( m_system_ver->GetStrictVer() <= W2K3_VER )
        list_head_name = "nt!IopDeviceClassNotifyList";
    else
        list_head_name = "nt!PnpDeviceClassNotifyList";

    if ( !m_sym_cache->GetSymbolOffset(list_head_name, true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
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
    context.output_list_pointer = output_list;

    WalkDeviceNode(0ULL, reinterpret_cast<void*>(&context), DeviceNodeCallback);
}

HRESULT WDbgArk::DeviceNodeCallback(WDbgArk* wdbg_ark_class, const ExtRemoteTyped &device_node, void* context) {
    WalkCallbackContext* cb_context = reinterpret_cast<WalkCallbackContext*>(context);

    std::stringstream info;

    info << std::setw(37) << "<exec cmd=\"!devnode " << std::hex << std::showbase << device_node.m_Offset;
    info << "\">!devnode" << "</exec>";

    try {
        ExtRemoteTyped target_dev_notify = const_cast<ExtRemoteTyped &>(device_node).Field("TargetDeviceNotify");

        wdbg_ark_class->WalkAnyListWithOffsetToRoutine(cb_context->list_head_name,
                                                       target_dev_notify.m_Offset,
                                                       0,
                                                       true,
                                                       GetPnpCallbackItemFunctionOffset(),
                                                       cb_context->type,
                                                       info.str(),
                                                       cb_context->output_list_pointer);
    }
    catch ( const ExtRemoteException &Ex ) {
        std::stringstream tmperr;
        tmperr << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;

        return Ex.GetStatus();
    }

    return S_OK;
}

}   // namespace wa
