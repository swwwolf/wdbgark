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

#include <string>
#include <iomanip>
#include <algorithm>
#include <utility>
#include <memory>

#include "objhelper.hpp"
#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "strings.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// base object manager helper class
//////////////////////////////////////////////////////////////////////////
WDbgArkObjHelper::WDbgArkObjHelper(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : m_inited(false),
      m_object_header_old(true),
      m_ObpInfoMaskToOffset(0),
      m_ObTypeIndexTableOffset(0),
      m_ObHeaderCookie(0),
      m_sym_cache(sym_cache),
      out(),
      warn(),
      err() {
    // determine object header format
    uint32_t type_index_offset = 0;

    // old header format
    if ( GetFieldOffset("nt!_OBJECT_HEADER", "TypeIndex", reinterpret_cast<PULONG>(&type_index_offset)) != 0 ) {
        m_inited = true;
    } else {
        m_object_header_old = false;  // new header format

        if ( !m_sym_cache->GetSymbolOffset("nt!ObpInfoMaskToOffset", true, &m_ObpInfoMaskToOffset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find nt!ObpInfoMaskToOffset" << endlerr;
            return;
        }

        if ( !m_sym_cache->GetSymbolOffset("nt!ObTypeIndexTable", true, &m_ObTypeIndexTableOffset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find nt!ObTypeIndexTable" << endlerr;
            return;
        }

        // Windows 10+
        uint64_t header_cookie_offset = 0;
        if ( m_sym_cache->GetSymbolOffset("nt!ObHeaderCookie", true, &header_cookie_offset) ) {
            m_ObHeaderCookie = ExtRemoteData(header_cookie_offset, sizeof(m_ObHeaderCookie)).GetUchar();
        }

        m_inited = true;
    }
}

WDbgArkObjHelper::ObjectsInfoResult WDbgArkObjHelper::GetObjectsInfo(const uint64_t directory_address,
                                                                     const std::string &root_path,
                                                                     const bool recursive) {
    uint64_t offset = directory_address;
    ObjectsInformation info;

    try {
        if ( !offset ) {
            if ( !m_sym_cache->GetSymbolOffset("nt!ObpRootDirectoryObject", true, &offset) ) {
                err << wa::showminus << __FUNCTION__ << ": failed to get nt!ObpRootDirectoryObject" << endlerr;
                return std::make_pair(E_UNEXPECTED, info);
            } else {
                ExtRemoteData directory_object_ptr(offset, g_Ext->m_PtrSize);
                offset = directory_object_ptr.GetPtr();
            }
        }

        ExtRemoteTyped directory_object("nt!_OBJECT_DIRECTORY", offset, false, nullptr, nullptr);
        ExtRemoteTyped buckets = directory_object.Field("HashBuckets");

        int num_buckets = buckets.GetTypeSize() / g_Ext->m_PtrSize;

        for ( int i = 0; i < num_buckets; i++ ) {
            if ( !buckets.m_Offset )
                continue;

            for ( ExtRemoteTyped directory_entry = *buckets[static_cast<ULONG>(i)];
                  directory_entry.m_Offset;
                  directory_entry = *directory_entry.Field("ChainLink") ) {
                ObjectInfo object_information;

                object_information.directory_object = directory_object;
                object_information.object = *directory_entry.Field("Object");

                std::pair<HRESULT, std::string> result = GetObjectName(object_information.object);

                if ( FAILED(result.first) )
                    continue;

                object_information.obj_name = result.second;
                object_information.full_path = root_path + object_information.obj_name;

                result = GetObjectTypeName(object_information.object);

                if ( FAILED(result.first) )
                    continue;

                object_information.type_name = result.second;

                // workaround for an infinite loop (broken crash dump with broken object directory)
                std::pair<ObjectsInformation::iterator, ObjectsInformation::iterator> iter_pair = \
                    info.equal_range(object_information.object.m_Offset);

                if ( iter_pair.first == iter_pair.second ) {    // not in map
                    info.insert(iter_pair.first, std::make_pair(object_information.object.m_Offset,
                                                                object_information));
                } else {    // already in map and this is strange
                    break;
                }

                if ( recursive && object_information.type_name == "Directory" ) {
                    object_information.full_path += "\\";

                    auto recursive_info = GetObjectsInfo(object_information.object.m_Offset,
                                                         object_information.full_path,
                                                         recursive);

                    if ( SUCCEEDED(recursive_info.first) )
                        info.insert(recursive_info.second.begin(), recursive_info.second.end());
                }
            }
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return std::make_pair(Ex.GetStatus(), info);
    }

    return std::make_pair(S_OK, info);
}

uint64_t WDbgArkObjHelper::FindObjectByName(const std::string &object_name,
                                            const uint64_t directory_address,
                                            const std::string &root_path,
                                            const bool recursive) {
    if ( object_name.empty() ) {
        err << wa::showminus << __FUNCTION__ << ": invalid object name" << endlerr;
        return 0ULL;
    }

    auto info = GetObjectsInfo(directory_address, root_path, recursive);

    if ( FAILED(info.first) ) {
        err << wa::showminus << __FUNCTION__ << ": GetObjectsInfo failed" << endlerr;
        return 0ULL;
    }

    std::string compare_full_path = root_path + object_name;

    if ( root_path == "\\" && object_name[0] == '\\' )
        compare_full_path = object_name;

    std::transform(compare_full_path.begin(), compare_full_path.end(), compare_full_path.begin(), tolower);

    for ( auto &object_info : info.second ) {
        std::string full_path = object_info.second.full_path;
        std::transform(full_path.begin(), full_path.end(), full_path.begin(), tolower);

        if ( full_path == compare_full_path )
            return object_info.second.object.m_Offset;
    }

    return 0ULL;
}

std::pair<HRESULT, ExtRemoteTyped> WDbgArkObjHelper::GetObjectHeader(const ExtRemoteTyped &object) {
    ExtRemoteTyped object_header;

    try {
        uint32_t offset = 0;

        if ( GetFieldOffset("nt!_OBJECT_HEADER", "Body", reinterpret_cast<PULONG>(&offset)) != 0 ) {
            err << wa::showminus << __FUNCTION__ << ": GetFieldOffset failed" << endlerr;
            return std::make_pair(E_UNEXPECTED, object_header);
        }

        if ( !offset ) {
            err << wa::showminus << __FUNCTION__ << ": body field is missing in nt!_OBJECT_HEADER" << endlerr;
            return std::make_pair(E_UNEXPECTED, object_header);
        }

        object_header.Set("nt!_OBJECT_HEADER", object.m_Offset - offset, false, NULL, NULL);
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return std::make_pair(Ex.GetStatus(), object_header);
    }

    return std::make_pair(S_OK, object_header);
}

std::pair<HRESULT, ExtRemoteTyped> WDbgArkObjHelper::GetObjectHeaderNameInfo(const ExtRemoteTyped &object_header) {
    ExtRemoteTyped object_header_name_info;

    try {
        ExtRemoteTyped& loc_object_header = const_cast<ExtRemoteTyped&>(object_header);

        if ( m_object_header_old ) {
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
            if ( m_ObpInfoMaskToOffset ) {
                ExtRemoteTyped info_mask = loc_object_header.Field("InfoMask");

                if ( info_mask.GetUchar() & HeaderNameInfoFlag ) {
                    ExtRemoteData name_info_mask_to_offset(
                        m_ObpInfoMaskToOffset +\
                        (info_mask.GetUchar() & (HeaderNameInfoFlag | (HeaderNameInfoFlag - 1))),
                        sizeof(uint8_t) );

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
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return std::make_pair(Ex.GetStatus(), object_header_name_info);
    }

    return std::make_pair(E_UNEXPECTED, object_header_name_info);
}

std::pair<HRESULT, std::string> WDbgArkObjHelper::GetObjectName(const ExtRemoteTyped &object) {
    std::string output_string = "*UNKNOWN*";

    std::pair<HRESULT, ExtRemoteTyped> result = GetObjectHeader(object);

    if ( FAILED(result.first) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get object header" << endlerr;
        return std::make_pair(result.first, output_string);
    }

    result = GetObjectHeaderNameInfo(result.second);

    if ( FAILED(result.first) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get object header name info" << endlerr;
        return std::make_pair(result.first, output_string);
    }

    ExtRemoteTyped unicode_string = result.second.Field("Name");

    return UnicodeStringStructToString(unicode_string);
}

std::pair<HRESULT, ExtRemoteTyped> WDbgArkObjHelper::GetObjectType(const ExtRemoteTyped &object) {
    ExtRemoteTyped object_type;

    try {
        auto result_header = GetObjectHeader(object);

        if ( FAILED(result_header.first) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get object header" << endlerr;
            return std::make_pair(result_header.first, object_type);
        }

        if ( m_object_header_old ) {
            object_type = result_header.second.Field("Type");
        } else {
            auto type_index = 0;

            if ( m_ObHeaderCookie ) {
                type_index = (m_ObHeaderCookie ^ result_header.second.Field("TypeIndex").GetUchar()) ^ \
                             static_cast<uint8_t>(result_header.second.m_Offset >> 8);
            } else {
                type_index = result_header.second.Field("TypeIndex").GetUchar();
            }

            ExtRemoteData object_type_data(m_ObTypeIndexTableOffset + type_index * g_Ext->m_PtrSize, g_Ext->m_PtrSize);
            object_type.Set("nt!_OBJECT_TYPE", object_type_data.GetPtr(), false, nullptr, nullptr);
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return std::make_pair(Ex.GetStatus(), object_type);
    }

    return std::make_pair(S_OK, object_type);
}

std::pair<HRESULT, std::string> WDbgArkObjHelper::GetObjectTypeName(const ExtRemoteTyped &object) {
    std::string output_string = "*UNKNOWN*";

    auto result_type = GetObjectType(object);

    if ( FAILED(result_type.first) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get object type" << endlerr;
        return std::make_pair(result_type.first, output_string);
    }

    return UnicodeStringStructToString(result_type.second.Field("Name"));
}

//////////////////////////////////////////////////////////////////////////
// driver object helper class
//////////////////////////////////////////////////////////////////////////
WDbgArkDrvObjHelper::WDbgArkDrvObjHelper(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                                         const ExtRemoteTyped &driver) : WDbgArkObjHelper(sym_cache),
                                                                         m_driver(driver) {}

WDbgArkDrvObjHelper::Table WDbgArkDrvObjHelper::GetMajorTable() {
    ExtRemoteTyped major_table = m_driver.Field("MajorFunction");

    Table table;

    for ( size_t i = 0; i < m_major_table_name.size(); i++ )
        table.push_back({ major_table[static_cast<int64_t>(i)].GetPtr(), m_major_table_name[i] });

    return table;
}

WDbgArkDrvObjHelper::Table WDbgArkDrvObjHelper::GetFastIoTable() {
    ExtRemoteTyped fast_io_dispatch = m_driver.Field("FastIoDispatch");
    auto fast_io_dispatch_ptr = fast_io_dispatch.GetPtr();

    Table table;

    if ( fast_io_dispatch_ptr ) {
        fast_io_dispatch_ptr += fast_io_dispatch.GetFieldOffset("FastIoCheckIfPossible");

        for ( size_t i = 0; i < m_fast_io_table_name.size(); i++ ) {
            ExtRemoteData fast_io_dispatch_data(fast_io_dispatch_ptr + i * g_Ext->m_PtrSize, g_Ext->m_PtrSize);
            table.push_back({ fast_io_dispatch_data.GetPtr(), m_fast_io_table_name[i] });
        }
    }

    return table;
}

WDbgArkDrvObjHelper::Table WDbgArkDrvObjHelper::GetFsFilterCbTable() {
    Table table;

    if ( m_driver.Field("DriverExtension").GetPtr() ) {
        ExtRemoteTyped fs_filter_callbacks = m_driver.Field("DriverExtension").Field("FsFilterCallbacks");
        auto fs_filter_callbacks_ptr = fs_filter_callbacks.GetPtr();

        if ( fs_filter_callbacks_ptr ) {
            fs_filter_callbacks_ptr += fs_filter_callbacks.GetFieldOffset("PreAcquireForSectionSynchronization");

            for ( size_t i = 0; i < m_fs_filter_cb_table_name.size(); i++ ) {
                ExtRemoteData fs_filter_callbacks_data(fs_filter_callbacks_ptr + i * g_Ext->m_PtrSize,
                                                       g_Ext->m_PtrSize);
                table.push_back({ fs_filter_callbacks_data.GetPtr(), m_fs_filter_cb_table_name[i] });
            }
        }
    }

    return table;
}

}   // namespace wa
