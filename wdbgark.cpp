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

#pragma warning(disable:4242)
#include <algorithm>

EXT_DECLARE_GLOBALS();

WDbgArk::WDbgArk()
{
    inited = false;
}

void WDbgArk::Init()
{
    if ( !IsInited() )
    {
        // get system version
        m_Control->GetSystemVersion(&platform_id,
                                    &major_build,
                                    &minor_build,
                                    NULL,
                                    0,
                                    NULL,
                                    &service_pack_number,
                                    NULL,
                                    0,
                                    NULL);

        is_cur_machine64 = IsCurMachine64();

        // reloads kernel-mode modules
        m_Symbols->Reload( "/f /n" );

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

        if ( minor_build < W8RTM_VER )
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

        inited = true;
    }
}

unsigned __int64 WDbgArk::FindObjectByName(const string &object_name,
                                           const unsigned __int64 directory_address)
{
    unsigned __int64 offset       = directory_address;
    string           compare_with = object_name;

    if ( object_name.empty() )
    {
        err << "Invalid object name" << endlerr;
        return 0;
    }

    transform( compare_with.begin(), compare_with.end(), compare_with.begin(), tolower );

    try
    {
        if ( !offset )
        {
            if ( !GetSymbolOffset( "nt!ObpRootDirectoryObject", true, &offset ) )
            {
                err << "Failed to get nt!ObpRootDirectoryObject" << endlerr;
                return 0;
            }
            else
            {
                ExtRemoteData directory_object_ptr( offset, m_PtrSize );
                offset = directory_object_ptr.GetPtr();
            }
        }

        ExtRemoteTyped directory_object( "nt!_OBJECT_DIRECTORY", offset, false, NULL, NULL );
        ExtRemoteTyped buckets = directory_object.Field( "HashBuckets" );

        for ( LONG64 i = 0; i < buckets.GetTypeSize() / m_PtrSize; i++ )
        {
            if ( !buckets.m_Offset )
                continue;

            for ( ExtRemoteTyped directory_entry = *buckets[i];
                  directory_entry.m_Offset;
                  directory_entry = *directory_entry.Field( "ChainLink" ) )
            {
                ExtRemoteTyped object = *directory_entry.Field( "Object" );

                string check_object_name;

                if ( SUCCEEDED( GetObjectName( object, check_object_name ) ) )
                {
                    transform( check_object_name.begin(), check_object_name.end(), check_object_name.begin(), tolower );

                    if ( check_object_name == compare_with )
                    {
                        return object.m_Offset;
                    }
                }
            }
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with object_name = " << object_name << " offset = ";
        err << std::hex << std::showbase << offset << endlerr;
    }

    return 0;
}

void WDbgArk::WalkAnyListWithOffsetToRoutine(const string &list_head_name,
                                             const unsigned __int64 offset_list_head,
                                             bool is_double,
                                             const unsigned long offset_to_routine,
                                             const string &type)
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
        ExtRemoteList list_head( offset, 0, is_double );

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() )
        {
            ExtRemoteData structure_data( list_head.GetNodeOffset() + offset_to_routine, m_PtrSize );

            unsigned __int64 notify_routine = structure_data.GetPtr();

            if ( notify_routine )
            {
                AnalyzeAddressAsRoutine( notify_routine, type, "" );
            }
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with list_head_name = " << list_head_name << " offset = ";
        err << std::hex << std::showbase << offset << endlerr;
    }
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
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with list_head_name = " << list_head_name << " offset = ";
        err << std::hex << std::showbase << offset << endlerr;
    }
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

        for ( __int64 i = 0; i < buckets.GetTypeSize() / m_PtrSize; i++ )
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
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with directory_address = ";
        err << std::hex << std::showbase << directory_address << endlerr;
    }
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
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with device_node_address = ";
        err << std::hex << std::showbase << device_node_address << endlerr;
    }
}

HRESULT WDbgArk::GetObjectHeader(const ExtRemoteTyped &object, ExtRemoteTyped &object_header)
{
    unsigned long offset = 0;

    GetFieldOffset( "nt!_OBJECT_HEADER", "Body", &offset );

    if ( !offset )
    {
        err << "Body field is missing in nt!_OBJECT_HEADER" << endlerr;
        return E_UNEXPECTED;
    }

    object_header.Set( "nt!_OBJECT_HEADER", object.m_Offset - offset, false, NULL, NULL );

    return S_OK;
}

HRESULT WDbgArk::GetObjectHeaderNameInfo(ExtRemoteTyped &object_header, ExtRemoteTyped &object_header_name_info)
{
    unsigned long type_index_offset = 0;

    GetFieldOffset( "nt!_OBJECT_HEADER", "TypeIndex", &type_index_offset );

    try
    {
        if ( !type_index_offset ) // old header format
        {
            ExtRemoteTyped name_info_offset = object_header.Field( "NameInfoOffset" );

            if ( name_info_offset.GetUchar() )
            {
                object_header_name_info.Set("nt!_OBJECT_HEADER_NAME_INFO",
                                            object_header.m_Offset - name_info_offset.GetUchar(),
                                            false,
                                            NULL,
                                            NULL);
                return S_OK;
            }
        }
        else // new header format
        {
            unsigned __int64 offset = 0;

            if ( GetSymbolOffset( "nt!ObpInfoMaskToOffset", true, &offset ) )
            {
                ExtRemoteTyped info_mask = object_header.Field( "InfoMask" );

                if ( info_mask.GetUchar() & HeaderNameInfoFlag )
                {
                    ExtRemoteData name_info_mask_to_offset(
                        offset + ( info_mask.GetUchar() & ( HeaderNameInfoFlag | ( HeaderNameInfoFlag - 1 ) ) ),
                        sizeof( unsigned char ) );

                    object_header_name_info.Set("nt!_OBJECT_HEADER_NAME_INFO",
                                                object_header.m_Offset - name_info_mask_to_offset.GetUchar(),
                                                false,
                                                NULL,
                                                NULL);

                    return S_OK;
                }
            }
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with object_header.m_Offset = ";
        err << std::hex << std::showbase << object_header.m_Offset << endlerr;
    }

    return E_UNEXPECTED;
}

HRESULT WDbgArk::GetObjectName(ExtRemoteTyped &object, string &object_name)
{
    ExtRemoteTyped object_header;
    ExtRemoteTyped object_header_name_info;

    if ( FAILED( GetObjectHeader( object, object_header ) ) )
    {
        err << "Failed to get object header" << endlerr;
        return E_UNEXPECTED;
    }

    if ( FAILED( GetObjectHeaderNameInfo( object_header, object_header_name_info ) ) )
    {
        err << "Failed to get object header name info" << endlerr;
        return E_UNEXPECTED;
    }

    return UnicodeStringStructToString( object_header_name_info.Field( "Name" ), object_name );
}

HRESULT WDbgArk::UnicodeStringStructToString(ExtRemoteTyped &unicode_string, string &output_string)
{
    try
    {
        ExtRemoteTyped buffer = *unicode_string.Field( "Buffer" );
        USHORT max_bytes = unicode_string.Field( "MaximumLength" ).GetUshort();

        if ( max_bytes )
        {
            wchar_t* test_name = new wchar_t[ max_bytes + 1 ];
            ZeroMemory( test_name, ( max_bytes + 1 ) * sizeof( wchar_t ) );

            buffer.ReadBuffer( test_name, max_bytes, true );

            wstring wide_string_name( test_name );
            delete test_name;

            output_string = wstring_to_string( wide_string_name );

            return S_OK;
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with unicode_string.m_Offset = ";
        err << std::hex << std::showbase << unicode_string.m_Offset << endlerr;
    }

    return E_INVALIDARG;
}

void WDbgArk::AnalyzeAddressAsRoutine(const unsigned __int64 address,
                                      const string &type,
                                      const string &additional_info)
{
    bool    suspicious        = false;
    string  symbol_name       = "";
    string  module_name       = "";
    string  image_name        = "";
    string  loaded_image_name = "";

    stringstream symbol_command_buf;

    if ( address )
    {
        symbol_name = "Unknown symbol";
        module_name = "Unknown module";

        if ( !SUCCEEDED( GetModuleNames( address, image_name, module_name, loaded_image_name ) ) )
            suspicious = true;

        symbol_command_buf << "<exec cmd=\"lmvm " << module_name << "\">" << module_name << "</exec>";

        if ( !SUCCEEDED( GetNameByOffset( address, symbol_name ) ) )
            suspicious = true;
    }

    if ( !suspicious )
    {
        out << "*    ";
        out << std::internal << std::setw( 18 ) << std::setfill( '0' ) << std::hex << std::showbase << address << std::right << std::setfill( ' ' ) << std::setw( 4 ) << ' ';
        out << std::left << std::setw( 40 ) << type << std::right << std::setw( 12 ) << ' ';
        out << std::left << std::setw( 70 ) << symbol_name << std::right << std::setw( 4 ) << ' ';
        out << std::left << std::setw( 30 ) << symbol_command_buf.str() << std::right << std::setw( 1 ) << ' ';
        out << endlout;
    }
    else
    {
        warn << "*    ";
        warn << std::internal << std::setw( 18 ) << std::setfill( '0' ) << std::hex << std::showbase << address << std::right << std::setfill( ' ' ) << std::setw( 4 ) << ' ';
        warn << std::left << std::setw( 40 ) << type << std::right << std::setw( 12 ) << ' ';
        warn << std::left << std::setw( 70 ) << symbol_name << std::right << std::setw( 4 ) << ' ';
        warn << std::left << std::setw( 30 ) << symbol_command_buf.str() << std::right << std::setw( 1 ) << ' ';
        warn << endlwarn;
    }

    if ( !additional_info.empty() )
    {
        out << additional_info << endlout;
    }
}

void WDbgArk::AnalyzeAddressAsSymbolPointer(const string &symbol_name,
                                            const string &type,
                                            const string &additional_info)
{
    unsigned __int64 offset = 0;

    if ( GetSymbolOffset( symbol_name.c_str(), true, &offset ) )
    {
        ExtRemoteData routine_ptr( offset, m_PtrSize );
        offset = routine_ptr.GetPtr();

        if ( offset )
        {
            AnalyzeAddressAsRoutine( offset, type, additional_info );
        }
    }
}

HRESULT WDbgArk::GetModuleNames(const unsigned __int64 address,
                                string &image_name,
                                string &module_name,
                                string &loaded_image_name)
{
    unsigned long    len1, len2, len3 = 0;
    unsigned __int64 module_base      = 0;
    unsigned long    module_index     = 0;

    if ( !address )
        return E_INVALIDARG;

    HRESULT err = m_Symbols->GetModuleByOffset( address, 0, &module_index, &module_base );

    if ( SUCCEEDED( err ) )
    {
        err = m_Symbols->GetModuleNames(module_index,
                                        module_base,
                                        NULL,
                                        0,
                                        &len1,
                                        NULL,
                                        0,
                                        &len2,
                                        NULL,
                                        0,
                                        &len3);

        if ( SUCCEEDED( err ) )
        {
            char* buf1 = new char[ len1 + 1 ];
            char* buf2 = new char[ len2 + 1 ];
            char* buf3 = new char[ len3 + 1 ];
            ZeroMemory( buf1, len1 + 1 );
            ZeroMemory( buf2, len2 + 1 );
            ZeroMemory( buf3, len3 + 1 );

            err = m_Symbols->GetModuleNames(module_index,
                                            module_base,
                                            buf1,
                                            len1 + 1,
                                            NULL,
                                            buf2,
                                            len2 + 1,
                                            NULL,
                                            buf3,
                                            len3 + 1,
                                            NULL);

            if ( SUCCEEDED( err ) )
            {
                image_name = buf1;
                transform( image_name.begin(), image_name.end(), image_name.begin(), tolower );

                module_name = buf2;
                transform( module_name.begin(), module_name.end(), module_name.begin(), tolower );

                loaded_image_name = buf3;
                transform( loaded_image_name.begin(), loaded_image_name.end(), loaded_image_name.begin(), tolower );
            }

            delete buf3;
            delete buf2;
            delete buf1;
        }
    }

    return err;
}

HRESULT WDbgArk::GetNameByOffset(const unsigned __int64 address, string &name)
{
    unsigned long    name_buffer_size = 0;
    unsigned __int64 displacement     = 0;
    HRESULT          err              = E_UNEXPECTED;
    stringstream     stream_name;

    if ( !address )
        return E_INVALIDARG;

    err = m_Symbols->GetNameByOffset( address, NULL, 0, &name_buffer_size, &displacement );

    if ( SUCCEEDED( err ) && name_buffer_size )
    {
        char* tmp_name = new char[ name_buffer_size + 1 ];
        ZeroMemory( tmp_name, name_buffer_size + 1 );

        err = m_Symbols->GetNameByOffset( address, tmp_name, name_buffer_size, NULL, NULL );

        if ( SUCCEEDED( err ) )
        {
            stream_name << tmp_name;

            if ( displacement )
                stream_name << "+" << std::hex << std::showbase << displacement;

            name = stream_name.str();
            //transform( name.begin(), name.end(), name.begin(), tolower );
        }

        delete tmp_name;
    }

    return err;
}