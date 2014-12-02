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

// TODO: DbgkLkmdRegisterCallback (WINDOWS 7+), ObRegisterCallbacks, CrashdmpCallTable, KdRegisterPowerHandler, IoRegisterIoTracking 

/*

"!systemcb /type type_name"

Type names are:

image
process
thread
registry
bugcheck
bugcheckreason
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

EXT_COMMAND(wa_systemcb,
            "Output kernel-mode registered callback(s)",
            "{type;s;o;type,Callback type name:\n"\
            "image, process, thread, registry, bugcheck, bugcheckreason, powersetting, callbackdir, shutdown, "\
            "shutdownlast, drvreinit, bootdrvreinit, fschange, nmi, logonsessionroutine, prioritycallback, pnp, lego, "\
            "debugprint}")
{
    string      type;
    walkresType output_list;
    
    RequireKernelMode();
    Init();

    if ( HasArg( "type" ) ) // callback type was provided
        type.assign( GetArgStr( "type" ) );

    out << "Displaying OS registered callback(s) " << type << endlout;

    WDbgArkAnalyze display;
    stringstream   tmp_stream;
    display.Init( &tmp_stream, AnalyzeTypeCallback );
    display.PrintFooter();
    
    try
    {
        if ( type.empty() )
        {
            for ( map <string, SystemCbCommand>::const_iterator citer = system_cb_commands.begin();
                  citer != system_cb_commands.end();
                  ++citer )
            {
                Call—orrespondingWalkListRoutine( citer, output_list );
            }
        }
        else
        {
            map <string, SystemCbCommand>::const_iterator citer = system_cb_commands.find( type );

            if ( citer != system_cb_commands.end() )
                Call—orrespondingWalkListRoutine( citer, output_list );
            else
                err << __FUNCTION__ << ": invalid type was specified" << endlerr;
        }

        string prev_list_head;

        for ( walkresType::iterator it = output_list.begin(); it != output_list.end(); ++it )
        {
            if ( prev_list_head != (*it).list_head_name )
            {
                out << "[+] " << (*it).list_head_name;

                if ( (*it).list_head_offset )
                    out << ": " << std::hex << std::showbase << (*it).list_head_offset;

                out << endlout;

                display.PrintHeader();
            }

            display.AnalyzeAddressAsRoutine( (*it).routine_address, (*it).type, (*it).info );
            display.PrintFooter();

            prev_list_head = (*it).list_head_name;
        }

        display.PrintFooter();

        output_list.clear();
    }
    catch( ExtInterruptException Ex )
    {
        throw Ex;
    }
}

void WDbgArk::Call—orrespondingWalkListRoutine(map <string, SystemCbCommand>::const_iterator &citer,
                                               walkresType &output_list)
{
    if ( citer->first == "registry" )
    {
        if ( m_minor_build == WXP_VER || m_minor_build == W2K3_VER )
        {
            WalkExCallbackList(citer->second.list_count_name,
                               citer->second.list_head_name,
                               citer->first,
                               output_list);
        }
        else
        {
            WalkAnyListWithOffsetToRoutine("nt!CallbackListHead",
                                           0,
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first,
                                           "",
                                           output_list);
        }
    }
    else if ( citer->first == "image" || citer->first == "process" || citer->first == "thread" )
    {
        WalkExCallbackList(citer->second.list_count_name,
                           citer->second.list_head_name,
                           citer->first,
                           output_list);
    }
    else if ( citer->first == "bugcheck" || citer->first == "bugcheckreason" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    }
    else if ( citer->first == "powersetting" && m_minor_build > W2K3_VER )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    }
    else if ( citer->first == "callbackdir" )
    {
        WalkCallbackDirectory( citer->first, output_list );
    }
    else if ( citer->first == "shutdown" || citer->first == "shutdownlast" )
    {
        WalkShutdownList( citer->second.list_head_name, citer->first, output_list );
    }
    else if ( citer->first == "drvreinit" || citer->first == "bootdrvreinit" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    }
    else if ( citer->first == "fschange" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    }
    else if ( citer->first == "nmi" && m_minor_build > WXP_VER )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    }
    else if ( citer->first == "logonsessionroutine" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first,
                                       "",
                                       output_list);
    }
    else if ( citer->first == "prioritycallback" && m_minor_build >= W7RTM_VER )
    {
        WalkExCallbackList(citer->second.list_count_name,
                           citer->second.list_head_name,
                           citer->first,
                           output_list);
    }
    else if ( citer->first == "pnp" )
    {
        WalkPnpLists( citer->first, output_list );
    }
    else if ( citer->first == "lego" )
    {
        AddSymbolPointer( citer->second.list_head_name, citer->first, "", output_list );
    }
    else if ( citer->first == "debugprint" && m_minor_build >= VISTA_RTM_VER )
    {
        if ( m_minor_build == VISTA_RTM_VER ) // vista rtm only
        {
            AddSymbolPointer( "nt!RtlpDebugPrintCallback", citer->first, "", output_list );
        }
        else // all others
        {
            WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                           0,
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first,
                                           "",
                                           output_list);
        }
    }
}

void WDbgArk::WalkExCallbackList(const string &list_count_name,
                                 const string &list_head_name,
                                 const string &type,
                                 walkresType &output_list)
{
    unsigned __int64 offset = 0;

    try
    {
        if ( !GetSymbolOffset( list_count_name.c_str(), true, &offset ) )
        {
            err << __FUNCTION__ << ": failed to get " << list_count_name << endlerr;
            return;
        }

        ExtRemoteData routine_count( offset, sizeof( unsigned long ) );

        if ( !GetSymbolOffset( list_head_name.c_str(), true, &offset ) )
        {
            err << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
            return;
        }

        unsigned __int64 list_head_offset = offset;

        unsigned long count = routine_count.GetUlong();

        for ( unsigned long i = 0; i < count; i++ )
        {
            ExtRemoteData notify_routine_list( offset + i * m_PtrSize, m_PtrSize );

            unsigned __int64 ex_callback_fast_ref = notify_routine_list.GetPtr();

            if ( ex_callback_fast_ref )
            {
                ExtRemoteData routine_block(
                    m_obj_helper.ExFastRefGetObject( ex_callback_fast_ref ) + GetTypeSize( "nt!_EX_RUNDOWN_REF" ),
                    m_PtrSize );

                unsigned __int64 notify_routine = routine_block.GetPtr();

                if ( notify_routine )
                {
                    OutputWalkInfo info = { notify_routine, type, "", list_head_name, 0, list_head_offset };
                    output_list.push_back( info );
                }
            }
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

//
// http://redplait.blogspot.ru/2010/08/cmregistercallbackex-on-vista.html
//
unsigned long WDbgArk::GetCmCallbackItemFunctionOffset()
{
    if ( IsCurMachine32() )
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
unsigned long WDbgArk::GetPowerCallbackItemFunctionOffset()
{
    if ( IsCurMachine32() )
        return 0x28;

    return 0x40;
}

unsigned long WDbgArk::GetPnpCallbackItemFunctionOffset()
{
    if ( IsCurMachine32() )
        return 0x14;

    return 0x20;
}

//Execute( "!object \\Callback" );
void WDbgArk::WalkCallbackDirectory(const string &type, walkresType &output_list)
{
    WalkCallbackContext context;

    context.type = type;
    context.output_list_pointer = &output_list;

    WalkDirectoryObject(m_obj_helper.FindObjectByName( "Callback", 0 ),
                        reinterpret_cast<void*>( &context ),
                        DirectoryObjectCallback);
}

HRESULT WDbgArk::DirectoryObjectCallback(WDbgArk* wdbg_ark_class, ExtRemoteTyped &object, void* context)
{
    string               object_name;
    WalkCallbackContext* cb_context     = reinterpret_cast<WalkCallbackContext*>( context );
    string               type           = cb_context->type;
    string               list_head_name = "\\Callback\\";

    if ( FAILED( wdbg_ark_class->m_obj_helper.GetObjectName( object, object_name ) ) )
    {
        stringstream warn;
        warn << __FUNCTION__ << ": failed to get object name" << endlwarn;
    }
    else
        list_head_name.append( object_name );

    // Signature + Lock
    const unsigned __int64 offset_list_head = object.m_Offset + g_Ext->m_PtrSize + g_Ext->m_PtrSize;

    // Link + CallbackObject
    const unsigned long offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" ) + g_Ext->m_PtrSize;

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

void WDbgArk::WalkShutdownList(const string &list_head_name, const string &type, walkresType &output_list)
{
    WalkCallbackContext context;

    context.type = type;
    context.list_head_name = list_head_name;
    context.output_list_pointer = &output_list;
    GetSymbolOffset( list_head_name.c_str(), true, &context.list_head_offset );

    WalkAnyListWithOffsetToObjectPointer(list_head_name,
                                         0,
                                         true,
                                         GetTypeSize( "nt!_LIST_ENTRY" ),
                                         reinterpret_cast<void*>( &context ),
                                         ShutdownListCallback);
}

HRESULT WDbgArk::ShutdownListCallback(WDbgArk* wdbg_ark_class, ExtRemoteData &object_pointer, void* context)
{
    WalkCallbackContext* cb_context = reinterpret_cast<WalkCallbackContext*>( context );
    string               type       = cb_context->type;

    try
    {
        ExtRemoteTyped device_object( "nt!_DEVICE_OBJECT", object_pointer.GetPtr(), false, NULL, NULL );
        ExtRemoteTyped driver_object = *device_object.Field( "DriverObject" );
        ExtRemoteTyped major_functions = driver_object.Field( "MajorFunction" );

        stringstream info;

        info << "<exec cmd=\"!devobj " << std::hex << std::showbase << object_pointer.GetPtr();
        info << "\">!devobj" << "</exec>" << " ";

        info << "<exec cmd=\"!devstack " << std::hex << std::showbase << object_pointer.GetPtr();
        info << "\">!devstack" << "</exec>" << " ";

        info << "<exec cmd=\"!drvobj " << std::hex << std::showbase << driver_object.m_Offset;
        info << " 7" << "\">!drvobj" << "</exec>";

        OutputWalkInfo winfo = { major_functions[(unsigned long )IRP_MJ_SHUTDOWN].GetPtr(),
                                 type,
                                 info.str(),
                                 cb_context->list_head_name,
                                 0,
                                 cb_context->list_head_offset };

        cb_context->output_list_pointer->push_back( winfo );
    }
    catch ( ExtRemoteException Ex )
    {
        stringstream err;
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;

        return Ex.GetStatus();
    }

    return S_OK;
}

// IopProfileNotifyList and IopDeviceClassNotifyList were replaced
// by PnpProfileNotifyList and PnpDeviceClassNotifyList in Vista+
void WDbgArk::WalkPnpLists(const string &type, walkresType &output_list)
{
    string           list_head_name    = "";
    unsigned __int64 offset            = 0;
    unsigned long    offset_to_routine = GetPnpCallbackItemFunctionOffset();

    if ( m_minor_build == WXP_VER || m_minor_build == W2K3_VER )
        list_head_name = "nt!IopProfileNotifyList";
    else
        list_head_name = "nt!PnpProfileNotifyList";

    //type_w_subtype.append( ":EventCategoryHardwareProfileChange" );

    WalkAnyListWithOffsetToRoutine( list_head_name, 0, 0, true, offset_to_routine, type, "", output_list );

    //type_w_subtype = type;

    if ( m_minor_build == WXP_VER || m_minor_build == W2K3_VER )
        list_head_name = "nt!IopDeviceClassNotifyList";
    else
        list_head_name = "nt!PnpDeviceClassNotifyList";

    //type_w_subtype.append( ":EventCategoryDeviceInterfaceChange" );

    if ( !GetSymbolOffset( list_head_name.c_str(), true, &offset ) )
        err << __FUNCTION__ << ": failed to get " << list_head_name << endlerr;
    else
    {
        for ( int i = 0; i < NOTIFY_DEVICE_CLASS_HASH_BUCKETS; i++ )
        {
            WalkAnyListWithOffsetToRoutine(list_head_name,
                                           offset + i * GetTypeSize( "nt!_LIST_ENTRY" ),
                                           0,
                                           true,
                                           offset_to_routine,
                                           type,
                                           "",
                                           output_list);
        }
    }

    //type_w_subtype = type;
    //type_w_subtype.append( ":EventCategoryTargetDeviceChange" );

    WalkCallbackContext context;

    context.type = type;
    context.list_head_name = "nt!IopRootDeviceNode";
    context.output_list_pointer = &output_list;

    WalkDeviceNode( 0, reinterpret_cast<void*>( &context ), DeviceNodeCallback );
}

HRESULT WDbgArk::DeviceNodeCallback(WDbgArk* wdbg_ark_class, ExtRemoteTyped &device_node, void* context)
{
    WalkCallbackContext* cb_context = reinterpret_cast<WalkCallbackContext*>( context );

    stringstream info;

    info << std::setw( 37 ) << "<exec cmd=\"!devnode " << std::hex << std::showbase << device_node.m_Offset;
    info << "\">!devnode" << "</exec>";

    wdbg_ark_class->WalkAnyListWithOffsetToRoutine(cb_context->list_head_name,
                                                   device_node.Field( "TargetDeviceNotify" ).m_Offset,
                                                   0,
                                                   true,
                                                   wdbg_ark_class->GetPnpCallbackItemFunctionOffset(),
                                                   cb_context->type,
                                                   info.str(),
                                                   *cb_context->output_list_pointer);

    return S_OK;
}