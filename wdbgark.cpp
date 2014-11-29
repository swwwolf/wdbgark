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

#pragma warning(disable:4242)
#include <algorithm>

EXT_DECLARE_GLOBALS();

HRESULT UnicodeStringStructToString(ExtRemoteTyped &unicode_string, string &output_string)
{
    try
    {
        ExtRemoteTyped buffer = *unicode_string.Field( "Buffer" );
        unsigned short len = unicode_string.Field( "Length" ).GetUshort();
        unsigned short maxlen = unicode_string.Field( "MaximumLength" ).GetUshort();

        if ( len == 0 && maxlen == 1 )
        {
            output_string = "";
            return S_OK;
        }

        if ( maxlen >= sizeof( wchar_t ) && ( maxlen % sizeof( wchar_t ) == 0 ) )
        {
            unsigned short max_len_wide = maxlen / sizeof( wchar_t ) + 1;
            wchar_t* test_name = new wchar_t[ max_len_wide ];

            ZeroMemory( test_name, max_len_wide * sizeof( wchar_t ) );
            buffer.ReadBuffer( test_name, maxlen, true );

            wstring wide_string_name( test_name );
            delete[] test_name;

            output_string = wstring_to_string( wide_string_name );

            return S_OK;
        }
    }
    catch ( ExtRemoteException Ex )
    {
        stringstream err;

        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return Ex.GetStatus();
    }
    /*
    catch( ... )
    {
        stringstream err;

        err << "Exception in " << __FUNCTION__ << " with unicode_string.m_Offset = ";
        err << std::hex << std::showbase << unicode_string.m_Offset << endlerr;
    }
    */

    return E_INVALIDARG;
}

bool WDbgArk::Init()
{
    if ( IsInited() )
        return true;

    m_obj_helper.Init();

    // get system version
    m_Control->GetSystemVersion(&m_platform_id,
                                &m_major_build,
                                &m_minor_build,
                                NULL,
                                0,
                                NULL,
                                &m_service_pack_number,
                                NULL,
                                0,
                                NULL);

    m_is_cur_machine64 = IsCurMachine64();

    // TODO: optimize by calculating offsets in constructor only once
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
    command_info.offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" );
    system_cb_commands["bugcheck"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!KeBugCheckReasonCallbackListHead";
    command_info.offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" );
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
    command_info.offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" ) + m_PtrSize;
    system_cb_commands["drvreinit"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!IopBootDriverReinitializeQueueHead";
    command_info.offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" ) + m_PtrSize;
    system_cb_commands["bootdrvreinit"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!IopFsNotifyChangeQueueHead";
    command_info.offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" ) + m_PtrSize;
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
    command_info.list_head_name = "nt!PspLegoNotifyRoutine"; // actually just a pointer
    system_cb_commands["lego"] = command_info;

    command_info.list_count_name = "";
    command_info.list_head_name = "nt!RtlpDebugPrintCallbackList";
    command_info.offset_to_routine = GetTypeSize( "nt!_LIST_ENTRY" );
    system_cb_commands["debugprint"] = command_info;

    command_info.offset_to_routine = 0;

    if ( m_minor_build < W8RTM_VER )
    {
        callout_names.push_back( "nt!PspW32ProcessCallout" );
        callout_names.push_back( "nt!PspW32ThreadCallout" );
        callout_names.push_back( "nt!ExGlobalAtomTableCallout" );
        callout_names.push_back( "nt!KeGdiFlushUserBatch" );
        callout_names.push_back( "nt!PopEventCallout" );
        callout_names.push_back( "nt!PopStateCallout" );
        callout_names.push_back( "nt!PspW32JobCallout" );
        callout_names.push_back( "nt!ExDesktopOpenProcedureCallout" );
        callout_names.push_back( "nt!ExDesktopOkToCloseProcedureCallout" );
        callout_names.push_back( "nt!ExDesktopCloseProcedureCallout" );
        callout_names.push_back( "nt!ExDesktopDeleteProcedureCallout" );
        callout_names.push_back( "nt!ExWindowStationOkToCloseProcedureCallout" );
        callout_names.push_back( "nt!ExWindowStationCloseProcedureCallout" );
        callout_names.push_back( "nt!ExWindowStationDeleteProcedureCallout" );
        callout_names.push_back( "nt!ExWindowStationParseProcedureCallout" );
        callout_names.push_back( "nt!ExWindowStationOpenProcedureCallout" );
        callout_names.push_back( "nt!IopWin32DataCollectionProcedureCallout" );
        callout_names.push_back( "nt!PopWin32InfoCallout" );
    }

    m_inited = true;

    return m_inited;
}

void WDbgArk::WalkAnyListWithOffsetToRoutine(const string &list_head_name,
                                             const unsigned __int64 offset_list_head,
                                             const unsigned long link_offset,
                                             bool is_double,
                                             const unsigned long offset_to_routine,
                                             const string &type,
                                             const string &ext_info,
                                             walkresType &output_list)
{
    unsigned __int64 offset = offset_list_head;

    if ( !offset_to_routine )
    {
        err << "Invalid parameter offset_to_routine was specified" << endlerr;
        return;
    }

    if ( !offset && !GetSymbolOffset( list_head_name.c_str(), true, &offset ) )
    {
        err << "Failed to get " << list_head_name << endlerr;
        return;
    }

    try
    {
        ExtRemoteList list_head( offset, link_offset, is_double );

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() )
        {
            ExtRemoteData structure_data( list_head.GetNodeOffset() + offset_to_routine, m_PtrSize );

            unsigned __int64 routine = structure_data.GetPtr();

            if ( routine )
            {
                OutputWalkInfo info = { routine, type, ext_info, list_head_name, list_head.GetNodeOffset() };
                output_list.push_back( info );
            }
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with list_head_name = " << list_head_name << " offset = ";
        err << std::hex << std::showbase << offset << endlerr;
    }
    */
}

void WDbgArk::WalkAnyListWithOffsetToObjectPointer(const string &list_head_name,
                                                   const unsigned __int64 offset_list_head,
                                                   bool is_double,
                                                   const unsigned long offset_to_object_pointer,
                                                   void* context,
                                                   pfn_any_list_w_pobject_walk_callback_routine callback)
{
    unsigned __int64 offset = offset_list_head;

    if ( !offset_to_object_pointer )
    {
        err << "Invalid parameter offset_to_object_pointer" << endlerr;
        return;
    }

    if ( !offset && !GetSymbolOffset( list_head_name.c_str(), true, &offset ) )
    {
        err << "Failed to get " << list_head_name << endlerr;
        return;
    }

    try
    {
        ExtRemoteList list_head( offset, 0, is_double );

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() )
        {
            ExtRemoteData object_pointer( list_head.GetNodeOffset() + offset_to_object_pointer, m_PtrSize );

            if ( !SUCCEEDED( callback( this, object_pointer, context ) ) )
            {
                err << __FUNCTION__ << ": error while invoking callback" << endlerr;
                return;
            }
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with list_head_name = " << list_head_name << " offset = ";
        err << std::hex << std::showbase << offset << endlerr;
    }
    */
}

void WDbgArk::WalkDirectoryObject(const unsigned __int64 directory_address,
                                  void* context,
                                  pfn_object_directory_walk_callback_routine callback)
{
    if ( !directory_address )
    {
        err << "Invalid directory address" << endlerr;
        return;
    }

    if ( !callback )
    {
        err << "Invalid callback address" << endlerr;
        return;
    }

    try
    {
        ExtRemoteTyped directory_object( "nt!_OBJECT_DIRECTORY", directory_address, false, NULL, NULL );
        ExtRemoteTyped buckets = directory_object.Field( "HashBuckets" );

        unsigned long num_buckets = buckets.GetTypeSize() / m_PtrSize;

        for ( __int64 i = 0; i < num_buckets; i++ )
        {
            for ( ExtRemoteTyped directory_entry = *buckets[i];
                  directory_entry.m_Offset;
                  directory_entry = *directory_entry.Field( "ChainLink" ) )
            {
                if ( !SUCCEEDED( callback( this, *directory_entry.Field( "Object" ), context ) ) )
                {
                    err << __FUNCTION__ << ": error while invoking callback" << endlerr;
                    return;
                }
            }
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with directory_address = ";
        err << std::hex << std::showbase << directory_address << endlerr;
    }
    */
}

void WDbgArk::WalkDeviceNode(const unsigned __int64 device_node_address,
                             void* context,
                             pfn_device_node_walk_callback_routine callback)
{
    unsigned __int64 offset = device_node_address;

    if ( !callback )
    {
        err << "Invalid callback address" << endlerr;
        return;
    }

    try
    {
        if ( !offset )
        {
            if ( !GetSymbolOffset( "nt!IopRootDeviceNode", true, &offset ) )
            {
                err << "Failed to get nt!IopRootDeviceNode" << endlerr;
                return;
            }
            else
            {
                ExtRemoteData device_node_ptr( offset, m_PtrSize );
                offset = device_node_ptr.GetPtr();
            }
        }

        ExtRemoteTyped device_node( "nt!_DEVICE_NODE", offset, false, NULL, NULL );

        for ( ExtRemoteTyped child_node = *device_node.Field( "Child" );
              child_node.m_Offset;
              child_node = *child_node.Field( "Sibling" ) )
        {
            if ( !SUCCEEDED( callback( this, child_node, context ) ) )
            {
                err << __FUNCTION__ << ": error while invoking callback" << endlerr;
                return;
            }
            
            WalkDeviceNode( child_node.m_Offset, context, callback );
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with device_node_address = ";
        err << std::hex << std::showbase << device_node_address << endlerr;
    }
    */
}

void WDbgArk::AddSymbolPointer(const string &symbol_name,
                               const string &type,
                               const string &additional_info,
                               walkresType &output_list)
{
    unsigned __int64 offset = 0;

    try
    {
        if ( GetSymbolOffset( symbol_name.c_str(), true, &offset ) )
        {
            ExtRemoteData routine_ptr( offset, m_PtrSize );
            offset = routine_ptr.GetPtr();

            if ( offset )
            {
                OutputWalkInfo info = { offset, type, additional_info, symbol_name, 0 };
                output_list.push_back( info );
            }
        }
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}