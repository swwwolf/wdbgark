/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2017  Vyacheslav Rusakoff
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

#include <sstream>
#include <memory>
#include <vector>
#include <utility>
#include <string>

#include "ddk.h"
#include "apisethlp.hpp"
#include "manipulators.hpp"
#include "systemver.hpp"

namespace wa {

WDbgArkApiSet::WDbgArkApiSet(const ExtRemoteTyped &apiset_header,
                             const std::shared_ptr<WDbgArkMemTableTyped> &memtable,
                             const std::shared_ptr<WDbgArkProcess> &process_helper,
                             const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb)
    : m_version(const_cast<ExtRemoteTyped&>(apiset_header).Field("Version").GetUlong()),
      m_header_offset(apiset_header.m_Offset),
      m_memtable(memtable),
      m_process_helper(process_helper),
      m_dummy_pdb(dummy_pdb) {
    if ( m_version != API_SET_VERSION_W7 && m_version != API_SET_VERSION_W81 && m_version != API_SET_VERSION_W10 ) {
        return;
    }

    if ( !m_memtable->IsValid() ) {
        return;
    }

    WDbgArkMemTableTyped::WalkResult walk_result;
    auto result = m_memtable->Walk(&walk_result);

    if ( !result ) {
        return;
    }

    result = Process(std::move(walk_result));

    if ( !result ) {
        return;
    }

    m_inited = true;
}

bool WDbgArkApiSet::Process(WDbgArkMemTableTyped::WalkResult &&walk_result) {
    try {
        for ( auto& entry : walk_result ) {
            auto name_offset = m_header_offset + entry.Field("NameOffset").GetUlong();
            auto name_length = entry.Field("NameLength").GetUlong();

            if ( !name_offset || !name_length ) {
                continue;
            }

            const size_t length = name_length / sizeof(wchar_t);

            ApiSetKey key;
            key.resize(length);
            ExtRemoteData(name_offset, name_length).ReadBuffer(key.data(), name_length);

            const auto [table_start, table_count] = GetDataInfo(entry);

            WDbgArkMemTableTyped table_value(nullptr, table_start, GetApiSetValueEntry());

            if ( !table_value.IsValid() ) {
                continue;
            }

            table_value.SetTableCount(table_count);

            WDbgArkMemTableTyped::WalkResult value_walk_result;
            auto result = table_value.Walk(&value_walk_result);

            if ( !result ) {
                continue;
            }

            result = ProcessValues(key, std::move(value_walk_result));

            if ( !result ) {
                continue;
            }
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return !m_api_sets.empty();
}

bool WDbgArkApiSet::ProcessValues(const std::wstring &key, WDbgArkMemTableTyped::WalkResult &&walk_result) {
    try {
        for ( auto& value : walk_result ) {
            auto value_offset = m_header_offset + value.Field("ValueOffset").GetUlong();
            auto value_length = value.Field("ValueLength").GetUlong();

            ApiSetHost host;

            if ( value_offset != 0 && value_length != 0 ) {
                const size_t length = value_length / sizeof(wchar_t);

                host.resize(length);
                ExtRemoteData(value_offset, value_length).ReadBuffer(host.data(), value_length);
            }

            m_api_sets[key].push_back(host);
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return !m_api_sets[key].empty();
}

WDbgArkApiSet::DataInfo WDbgArkApiSet::GetDataInfo(ExtRemoteTyped &entry) {
    uint64_t table_start = 0ULL;
    uint32_t table_count = 0;

    try {
        auto data_offset = m_header_offset + entry.Field("DataOffset").GetUlong();

        if ( m_version == API_SET_VERSION_W7 || m_version == API_SET_VERSION_W81 ) {
            auto apiset_value_array = m_dummy_pdb->GetShortName() + "!" + GetApiSetValueArray();
            auto value_array = ExtRemoteTyped(apiset_value_array.c_str(),
                                              data_offset,
                                              false,
                                              nullptr,
                                              nullptr);

            table_start = value_array.Field("Array").m_Offset;
            table_count = value_array.Field("Count").GetUlong();
        } else {
            table_start = data_offset;
            table_count = entry.Field("DataCount").GetUlong();
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return { table_start, table_count };
}

std::string GetApiSetNamespace() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return std::string();
    }

    if ( system_ver.IsBuildInRangeStrict(W7RTM_VER, W8RTM_VER) ) {
        return std::string("_API_SET_NAMESPACE_ARRAY_W7");
    } else if ( system_ver.GetStrictVer() == W81RTM_VER ) {
        return std::string("_API_SET_NAMESPACE_ARRAY_W81");
    } else if ( system_ver.GetStrictVer() >= W10RTM_VER ) {
        return std::string("_API_SET_NAMESPACE_W10");
    }

    return std::string();
}

std::string GetApiSetNamespaceEntry() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return std::string();
    }

    if ( system_ver.IsBuildInRangeStrict(W7RTM_VER, W8RTM_VER) ) {
        return std::string("_API_SET_NAMESPACE_ENTRY_W7");
    } else if ( system_ver.GetStrictVer() == W81RTM_VER ) {
        return std::string("_API_SET_NAMESPACE_ENTRY_W81");
    } else if ( system_ver.GetStrictVer() >= W10RTM_VER ) {
        return std::string("_API_SET_NAMESPACE_ENTRY_W10");
    }

    return std::string();
}

std::string GetApiSetValueArray() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return std::string();
    }

    if ( system_ver.IsBuildInRangeStrict(W7RTM_VER, W8RTM_VER) ) {
        return std::string("_API_SET_VALUE_ARRAY_W7");
    } else if ( system_ver.GetStrictVer() == W81RTM_VER ) {
        return std::string("_API_SET_VALUE_ARRAY_W81");
    }

    return std::string();
}

std::string GetApiSetValueEntry() {
    WDbgArkSystemVer system_ver;

    if ( !system_ver.IsInited() ) {
        return std::string();
    }

    if ( system_ver.IsBuildInRangeStrict(W7RTM_VER, W8RTM_VER) ) {
        return std::string("_API_SET_VALUE_ENTRY_W7");
    } else if ( system_ver.GetStrictVer() == W81RTM_VER ) {
        return std::string("_API_SET_VALUE_ENTRY_W81");
    } else if ( system_ver.GetStrictVer() >= W10RTM_VER ) {
        return std::string("_API_SET_VALUE_ENTRY_W10");
    }

    return std::string();
}

}   // namespace wa
