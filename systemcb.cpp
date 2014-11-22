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

EXT_COMMAND(systemcb,
            "Output the kernel-mode OS registered callback(s)\n",
            "{type;s;o;type,Callback type name}")
{
    string type = "";

    RequireKernelMode();

    Init();

    if ( HasArg( "type" ) ) // callback type was provided
        type.assign( GetArgStr( "type" ) );

    out << "******" << endlout;
    out << "*    ";
    out << std::left << std::setw( 16 ) << "Address" << std::right << std::setw( 6 ) << ' ';
    out << std::left << std::setw( 40 ) << "Type:Subtype" << std::right << std::setw( 12 ) << ' ';
    out << std::left << std::setw( 70 ) << "Symbol" << std::right << std::setw( 4 ) << ' ';
    out << std::left << std::setw( 30 ) << "Module" << std::right << std::setw( 1 ) << ' ';
    out << "*" << endlout;
    out << "******" << endlout;

    if ( type.empty() )
    {
        for ( map <string, SystemCbCommand>::const_iterator citer = system_cb_commands.begin();
              citer != system_cb_commands.end();
              ++citer )
        {
            Call—orrespondingWalkListRoutine( citer );
        }
    }
    else
    {
        map <string, SystemCbCommand>::const_iterator citer = system_cb_commands.find( type );

        if ( citer != system_cb_commands.end() )
        {
            Call—orrespondingWalkListRoutine( citer );
        }
        else
        {
            err << "Invalid type was specified" << endlerr;
        }
    }

    out << "******" << endlout;
}

void WDbgArk::Call—orrespondingWalkListRoutine(map <string, SystemCbCommand>::const_iterator &citer)
{
    if ( citer->first == "registry" )
    {
        if ( minor_build == WXP_VER || minor_build == W2K3_VER )
        {
            WalkExCallbackList( citer->second.list_count_name, citer->second.list_head_name, citer->first );
        }
        else
        {
            WalkAnyListWithOffsetToRoutine("nt!CallbackListHead",
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first);
        }
    }
    else if ( citer->first == "image" || citer->first == "process" || citer->first == "thread" )
    {
        WalkExCallbackList( citer->second.list_count_name, citer->second.list_head_name, citer->first );
    }
    else if ( citer->first == "bugcheck" || citer->first == "bugcheckreason" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first);
    }
    else if ( citer->first == "powersetting" && minor_build > W2K3_VER )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first);
    }
    else if ( citer->first == "callbackdir" )
    {
        WalkCallbackDirectory( citer->first );
    }
    else if ( citer->first == "shutdown" || citer->first == "shutdownlast" )
    {
        WalkShutdownList( citer->second.list_head_name, citer->first );
    }
    else if ( citer->first == "drvreinit" || citer->first == "bootdrvreinit" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first);
    }
    else if ( citer->first == "fschange" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       true,
                                       citer->second.offset_to_routine,
                                       citer->first);
    }
    else if ( citer->first == "nmi" && minor_build > WXP_VER )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first);
    }
    else if ( citer->first == "logonsessionroutine" )
    {
        WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                       0,
                                       false,
                                       citer->second.offset_to_routine,
                                       citer->first);
    }
    else if ( citer->first == "prioritycallback" && minor_build >= W7RTM_VER )
    {
        WalkExCallbackList( citer->second.list_count_name, citer->second.list_head_name, citer->first );
    }
    else if ( citer->first == "pnp" )
    {
        WalkPnpLists( citer->first );
    }
    else if ( citer->first == "lego" )
    {
        AnalyzeAddressAsSymbolPointer( citer->second.list_head_name, citer->first, "" );
    }
    else if ( citer->first == "debugprint" && minor_build >= VISTA_RTM_VER )
    {
        if ( minor_build == VISTA_RTM_VER ) // vista rtm only
        {
            AnalyzeAddressAsSymbolPointer( "nt!RtlpDebugPrintCallback", citer->first, "" );
        }
        else // all others
        {
            WalkAnyListWithOffsetToRoutine(citer->second.list_head_name,
                                           0,
                                           true,
                                           citer->second.offset_to_routine,
                                           citer->first);
        }
    }
}

void WDbgArk::WalkExCallbackList(const string &list_count_name, const string &list_head_name, const string &type)
{
    unsigned __int64 offset = 0;
   
    bool bool_error = GetSymbolOffset( list_count_name.c_str(), true, &offset );

    if ( !bool_error )
    {
        err << "Failed to get " << list_count_name << endlerr;
        return;
    }

    ExtRemoteData routine_count( offset, sizeof( unsigned long ) );

    bool_error = GetSymbolOffset( list_head_name.c_str(), true, &offset );

    if ( !bool_error )
    {
        err << "Failed to get " << list_head_name << endlerr;
        return;
    }

    try
    {
        unsigned long count = routine_count.GetUlong();
        
        for ( unsigned long i = 0; i < count; i++ )
        {
            ExtRemoteData notify_routine_list( offset + i * m_PtrSize, m_PtrSize );

            unsigned __int64 ex_callback_fast_ref = notify_routine_list.GetPtr();

            if ( ex_callback_fast_ref )
            {
                ExtRemoteData routine_block(
                    ExFastRefGetObject( ex_callback_fast_ref ) + GetTypeSize( "nt!_EX_RUNDOWN_REF" ),
                    m_PtrSize );

                unsigned __int64 notify_routine = routine_block.GetPtr();

                if ( notify_routine )
                {
                    AnalyzeAddressAsRoutine( notify_routine, type, "" );
                }
            }
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with list_count_name = " << list_count_name;
        err << " list_head_name = " << list_head_name << endlerr;
    }
}

//
// http://redplait.blogspot.ru/2010/08/cmregistercallbackex-on-vista.html
//
unsigned long WDbgArk::GetCmCallbackItemFunctionOffset()
{
    if ( IsCurMachine32() )
        return 0x1C;

    if ( minor_build >= VISTA_RTM_VER && minor_build < W7RTM_VER )
        return 0x30;
    else if ( minor_build >= W7RTM_VER )
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
void WDbgArk::WalkCallbackDirectory(const string &type)
{    
    WalkDirectoryObject(FindObjectByName( "Callback", 0 ),
                        reinterpret_cast<void*>( const_cast<string*>( &type ) ),
                        DirectoryObjectCallback);
}

HRESULT WDbgArk::DirectoryObjectCallback(WDbgArk* wdbg_ark_class, ExtRemoteTyped &object, void* context)
{
    string object_name;
    string type = *reinterpret_cast<string*>( context );

    if ( FAILED( wdbg_ark_class->GetObjectName( object, object_name ) ) )
    {
        wdbg_ark_class->warn << "Failed to get object name" << endlwarn;
    }
    else
    {
        type.append( ":" );
        type.append( object_name );
    }

    // Signature + Lock
    const unsigned __int64 offset_list_head = object.m_Offset + wdbg_ark_class->m_PtrSize + wdbg_ark_class->m_PtrSize;

    // Link + CallbackObject
    const unsigned long offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" ) + wdbg_ark_class->m_PtrSize;

    wdbg_ark_class->WalkAnyListWithOffsetToRoutine("",
                                                   offset_list_head,
                                                   true,
                                                   offset_to_routine,
                                                   type);

    return S_OK;
}

void WDbgArk::WalkShutdownList(const string &list_head_name, const string &type)
{
    WalkAnyListWithOffsetToObjectPointer(list_head_name,
                                         0,
                                         true,
                                         GetTypeSize( "nt!_LIST_ENTRY" ),
                                         reinterpret_cast<void*>( const_cast<string*>( &type ) ),
                                         ShutdownListCallback);
}

HRESULT WDbgArk::ShutdownListCallback(WDbgArk* wdbg_ark_class, ExtRemoteData &object_pointer, void* context)
{
    string type = *reinterpret_cast<string*>( context );

    try
    {
        ExtRemoteTyped device_object( "nt!_DEVICE_OBJECT", object_pointer.GetPtr(), false, NULL, NULL );
        ExtRemoteTyped driver_object = *device_object.Field( "DriverObject" );
        ExtRemoteTyped major_functions = driver_object.Field( "MajorFunction" );

        stringstream info;

        info << "*    ^^^^^^^^^^^^^^^^^^\n";
        info << "*    <exec cmd=\"!devobj " << std::hex << std::showbase << object_pointer.GetPtr() << "\">!devobj   " << std::hex << std::showbase << object_pointer.GetPtr() << "</exec>\n";
        info << "*    <exec cmd=\"!devstack " << std::hex << std::showbase << object_pointer.GetPtr() << "\">!devstack " << std::hex << std::showbase << object_pointer.GetPtr() << "</exec>\n";
        info << "*    <exec cmd=\"!drvobj " << std::hex << std::showbase << driver_object.m_Offset << " 7" << "\">!drvobj   " << std::hex << std::showbase << driver_object.m_Offset << " 7" << "</exec>\n";
        info << "***";

        wdbg_ark_class->AnalyzeAddressAsRoutine( major_functions[(unsigned long )IRP_MJ_SHUTDOWN].GetPtr(), type, info.str() );
    }
    catch( ... )
    {
        wdbg_ark_class->err << "Exception in " << __FUNCTION__ << " with object_pointer.m_Offset = ";
        wdbg_ark_class->err << std::hex << std::showbase << object_pointer.m_Offset << endlerr;

        return E_POINTER;
    }

    return S_OK;
}

// IopProfileNotifyList and IopDeviceClassNotifyList were replaced by PnpProfileNotifyList and PnpDeviceClassNotifyList in Vista+
void WDbgArk::WalkPnpLists(const string &type)
{
    string           list_head_name    = "";
    string           type_w_subtype    = type;
    unsigned __int64 offset            = 0;
    unsigned long    offset_to_routine = GetPnpCallbackItemFunctionOffset();

    if ( minor_build == WXP_VER || minor_build == W2K3_VER )
    {
        list_head_name = "nt!IopProfileNotifyList";
    }
    else
    {
        list_head_name = "nt!PnpProfileNotifyList";
    }

    type_w_subtype.append( ":EventCategoryHardwareProfileChange" );

    WalkAnyListWithOffsetToRoutine( list_head_name, 0, true, offset_to_routine, type_w_subtype );

    type_w_subtype = type;

    if ( minor_build == WXP_VER || minor_build == W2K3_VER )
    {
        list_head_name = "nt!IopDeviceClassNotifyList";
    }
    else
    {
        list_head_name = "nt!PnpDeviceClassNotifyList";
    }

    type_w_subtype.append( ":EventCategoryDeviceInterfaceChange" );

    if ( !GetSymbolOffset( list_head_name.c_str(), true, &offset ) )
    {
        err << "Failed to get " << list_head_name << endlerr;
    }
    else
    {
        for ( int i = 0; i < NOTIFY_DEVICE_CLASS_HASH_BUCKETS; i++ )
        {
            WalkAnyListWithOffsetToRoutine("",
                                           offset + i * GetTypeSize( "nt!_LIST_ENTRY" ),
                                           true,
                                           offset_to_routine,
                                           type_w_subtype);
        }
    }

    type_w_subtype = type;
    type_w_subtype.append( ":EventCategoryTargetDeviceChange" );

    WalkDeviceNode( 0, reinterpret_cast<void*>( const_cast<string*>( &type_w_subtype ) ), DeviceNodeCallback );
}

HRESULT WDbgArk::DeviceNodeCallback(WDbgArk* wdbg_ark_class, ExtRemoteTyped &device_node, void* context)
{
    wdbg_ark_class->WalkAnyListWithOffsetToRoutine("",
                                                   device_node.Field( "TargetDeviceNotify" ).m_Offset,
                                                   true,
                                                   wdbg_ark_class->GetPnpCallbackItemFunctionOffset(),
                                                   *reinterpret_cast<string*>( context ));

    return S_OK;
}