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
#include <iomanip>
#include <algorithm>
#include <utility>
#include <memory>

#include "objhelper.hpp"
#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "strings.hpp"

bool WDbgArkObjHelper::Init(void) {
    if ( IsInited() )
        return true;

    // determine object header format
    unsigned __int32 type_index_offset = 0;

    // old header format
    if ( GetFieldOffset("nt!_OBJECT_HEADER", "TypeIndex", reinterpret_cast<PULONG>(&type_index_offset)) != 0 ) {
        object_header_old = true;
        m_inited = true;
    } else {
        // new header format
        object_header_old = false;

        if ( g_Ext->GetSymbolOffset("nt!ObpInfoMaskToOffset", true, &ObpInfoMaskToOffset) )
            m_inited = true;
    }

    return m_inited;
}

unsigned __int64 WDbgArkObjHelper::FindObjectByName(const std::string &object_name,
                                                    const unsigned __int64 directory_address) {
    unsigned __int64 offset       = directory_address;
    std::string      compare_with = object_name;

    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return 0;
    }

    if ( object_name.empty() ) {
        err << __FUNCTION__ << ": invalid object name" << endlerr;
        return 0;
    }

    std::transform(compare_with.begin(), compare_with.end(), compare_with.begin(), tolower);

    try {
        if ( !offset ) {
            if ( !g_Ext->GetSymbolOffset("nt!ObpRootDirectoryObject", true, &offset) ) {
                err << __FUNCTION__ << ": failed to get nt!ObpRootDirectoryObject" << endlerr;
                return 0;
            } else {
                ExtRemoteData directory_object_ptr(offset, g_Ext->m_PtrSize);
                offset = directory_object_ptr.GetPtr();
            }
        }

        ExtRemoteTyped directory_object("nt!_OBJECT_DIRECTORY", offset, false, NULL, NULL);
        ExtRemoteTyped buckets = directory_object.Field("HashBuckets");

        const unsigned __int32 num_buckets = buckets.GetTypeSize() / g_Ext->m_PtrSize;

        for ( unsigned __int32 i = 0; i < num_buckets; i++ ) {
            if ( !buckets.m_Offset )
                continue;

            for ( ExtRemoteTyped directory_entry = *buckets[static_cast<ULONG>(i)];
                  directory_entry.m_Offset;
                  directory_entry = *directory_entry.Field("ChainLink") ) {
                ExtRemoteTyped object = *directory_entry.Field("Object");

                std::pair<HRESULT, std::string> result = GetObjectName(object);

                if ( SUCCEEDED(result.first) ) {
                    std::string check_object_name = result.second;
                    std::transform(check_object_name.begin(),
                                   check_object_name.end(),
                                   check_object_name.begin(),
                                   tolower);

                    if ( check_object_name == compare_with ) {
                        return object.m_Offset;
                    }
                }
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return 0;
}

std::pair<HRESULT, ExtRemoteTyped> WDbgArkObjHelper::GetObjectHeader(const ExtRemoteTyped &object) {
    unsigned __int32 offset = 0;
    ExtRemoteTyped   object_header;

    try {
        ExtRemoteTyped loc_object = object;

        if ( !IsInited() ) {
            err << __FUNCTION__ << ": class is not initialized" << endlerr;
            return std::make_pair(E_NOT_VALID_STATE, object_header);
        }

        if ( GetFieldOffset("nt!_OBJECT_HEADER", "Body", reinterpret_cast<PULONG>(&offset)) != 0 ) {
            err << __FUNCTION__ << ": GetFieldOffset failed" << endlerr;
            return std::make_pair(E_UNEXPECTED, object_header);
        }

        if ( !offset ) {
            err << __FUNCTION__ << ": body field is missing in nt!_OBJECT_HEADER" << endlerr;
            return std::make_pair(E_UNEXPECTED, object_header);
        }

        object_header.Set("nt!_OBJECT_HEADER", object.m_Offset - offset, false, NULL, NULL);
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return std::make_pair(Ex.GetStatus(), object_header);
    }

    return std::make_pair(S_OK, object_header);
}

std::pair<HRESULT, ExtRemoteTyped> WDbgArkObjHelper::GetObjectHeaderNameInfo(const ExtRemoteTyped &object_header) {
    ExtRemoteTyped object_header_name_info;

    try {
        ExtRemoteTyped loc_object_header = object_header;

        if ( !IsInited() ) {
            err << __FUNCTION__ << ": class is not initialized" << endlerr;
            return std::make_pair(E_NOT_VALID_STATE, object_header_name_info);
        }

        if ( object_header_old ) {
            ExtRemoteTyped name_info_offset = loc_object_header.Field("NameInfoOffset");

            if ( name_info_offset.GetUchar() ) {
                object_header_name_info.Set("nt!_OBJECT_HEADER_NAME_INFO",
                                            object_header.m_Offset - name_info_offset.GetUchar(),
                                            false,
                                            NULL,
                                            NULL);
                return std::make_pair(S_OK, object_header_name_info);
            }
        } else {
            if ( ObpInfoMaskToOffset ) {
                ExtRemoteTyped info_mask = loc_object_header.Field("InfoMask");

                if ( info_mask.GetUchar() & HeaderNameInfoFlag ) {
                    ExtRemoteData name_info_mask_to_offset(
                        ObpInfoMaskToOffset + (info_mask.GetUchar() & (HeaderNameInfoFlag | (HeaderNameInfoFlag - 1))),
                        sizeof(unsigned char) );

                    object_header_name_info.Set("nt!_OBJECT_HEADER_NAME_INFO",
                                                loc_object_header.m_Offset - name_info_mask_to_offset.GetUchar(),
                                                false,
                                                NULL,
                                                NULL);

                    return std::make_pair(S_OK, object_header_name_info);
                }
            }
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return std::make_pair(Ex.GetStatus(), object_header_name_info);
    }

    return std::make_pair(E_UNEXPECTED, object_header_name_info);
}

std::pair<HRESULT, std::string> WDbgArkObjHelper::GetObjectName(const ExtRemoteTyped &object) {
    std::string output_string = "";

    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return std::make_pair(E_NOT_VALID_STATE, output_string);
    }

    std::pair<HRESULT, ExtRemoteTyped> result = GetObjectHeader(object);

    if ( !SUCCEEDED(result.first) ) {
        err << __FUNCTION__ << ": failed to get object header" << endlerr;
        return std::make_pair(result.first, output_string);
    }

    result = GetObjectHeaderNameInfo(result.second);

    if ( !SUCCEEDED(result.first) ) {
        err << __FUNCTION__ << ": failed to get object header name info" << endlerr;
        return std::make_pair(result.first, output_string);
    }

    ExtRemoteTyped unicode_string = result.second.Field("Name");

    return UnicodeStringStructToString(unicode_string);
}
