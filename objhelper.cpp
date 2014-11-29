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

#include <iomanip>
#include <algorithm>
using namespace std;

#include "objhelper.hpp"
#include "wdbgark.hpp"

bool WDbgArkObjHelper::Init(void)
{
    if ( IsInited() )
        return true;

    // determine object header format
    unsigned long type_index_offset = 0;

    GetFieldOffset( "nt!_OBJECT_HEADER", "TypeIndex", &type_index_offset );

    if ( !type_index_offset ) // old header format
    {
        object_header_old = true;
        m_inited = true;
    }
    else // new header format
    {
        object_header_old = false;

        if ( g_Ext->GetSymbolOffset( "nt!ObpInfoMaskToOffset", true, &ObpInfoMaskToOffset ) )
            m_inited = true;
    }

    return m_inited;
}

unsigned __int64 WDbgArkObjHelper::FindObjectByName(const string &object_name,
                                                    const unsigned __int64 directory_address)
{
    unsigned __int64 offset       = directory_address;
    string           compare_with = object_name;

    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return 0;
    }

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
            if ( !g_Ext->GetSymbolOffset( "nt!ObpRootDirectoryObject", true, &offset ) )
            {
                err << "Failed to get nt!ObpRootDirectoryObject" << endlerr;
                return 0;
            }
            else
            {
                ExtRemoteData directory_object_ptr( offset, g_Ext->m_PtrSize );
                offset = directory_object_ptr.GetPtr();
            }
        }

        ExtRemoteTyped directory_object( "nt!_OBJECT_DIRECTORY", offset, false, NULL, NULL );
        ExtRemoteTyped buckets = directory_object.Field( "HashBuckets" );

        unsigned long num_buckets = buckets.GetTypeSize() / g_Ext->m_PtrSize;

        for ( LONG64 i = 0; i < num_buckets; i++ )
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
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with object_name = " << object_name << " offset = ";
        err << std::hex << std::showbase << offset << endlerr;
    }
    */

    return 0;
}

HRESULT WDbgArkObjHelper::GetObjectHeader(const ExtRemoteTyped &object, ExtRemoteTyped &object_header)
{
    unsigned long offset = 0;

    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return E_NOT_VALID_STATE;
    }

    GetFieldOffset( "nt!_OBJECT_HEADER", "Body", &offset );

    if ( !offset )
    {
        err << "Body field is missing in nt!_OBJECT_HEADER" << endlerr;
        return E_UNEXPECTED;
    }

    try
    {
        object_header.Set( "nt!_OBJECT_HEADER", object.m_Offset - offset, false, NULL, NULL );
    }
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return Ex.GetStatus();
    }

    return S_OK;
}

HRESULT WDbgArkObjHelper::GetObjectHeaderNameInfo(ExtRemoteTyped &object_header, ExtRemoteTyped &object_header_name_info)
{
    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return E_NOT_VALID_STATE;
    }

    try
    {
        if ( object_header_old ) // old header format
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
            if ( ObpInfoMaskToOffset )
            {
                ExtRemoteTyped info_mask = object_header.Field( "InfoMask" );

                if ( info_mask.GetUchar() & HeaderNameInfoFlag )
                {
                    ExtRemoteData name_info_mask_to_offset(
                        ObpInfoMaskToOffset + ( info_mask.GetUchar() & ( HeaderNameInfoFlag | ( HeaderNameInfoFlag - 1 ) ) ),
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
    catch ( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return Ex.GetStatus();
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with object_header.m_Offset = ";
        err << std::hex << std::showbase << object_header.m_Offset << endlerr;
    }
    */

    return E_UNEXPECTED;
}

HRESULT WDbgArkObjHelper::GetObjectName(ExtRemoteTyped &object, string &object_name)
{
    ExtRemoteTyped object_header;
    ExtRemoteTyped object_header_name_info;

    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return E_NOT_VALID_STATE;
    }

    HRESULT res = GetObjectHeader( object, object_header );

    if ( FAILED( res ) )
    {
        err << "Failed to get object header" << endlerr;
        return res;
    }

    res = GetObjectHeaderNameInfo( object_header, object_header_name_info );

    if ( FAILED( res ) )
    {
        err << "Failed to get object header name info" << endlerr;
        return res;
    }

    return UnicodeStringStructToString( object_header_name_info.Field( "Name" ), object_name );
}

