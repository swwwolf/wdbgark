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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef APISETHLP_HPP_
#define APISETHLP_HPP_

#include <engextcpp.hpp>

#include <sstream>
#include <memory>
#include <vector>
#include <map>

#include "memtable.hpp"
#include "process.hpp"

namespace wa {

std::string GetApiSetNamespace();
std::string GetApiSetNamespaceEntry();
std::string GetApiSetValueArray();
std::string GetApiSetValueEntry();

// You have to set process implicitly before class construction if you want to walk process' Api Set table
class WDbgArkApiSet {
 public:
    using ApiSetKey = std::wstring;
    using ApiSetHost = std::wstring;
    using ApiSetHosts = std::vector<ApiSetHost>;
    using ApiSets = std::map<ApiSetKey, ApiSetHosts>;

    WDbgArkApiSet(const ExtRemoteTyped &apiset_header,
                  const std::shared_ptr<WDbgArkMemTableTyped> &memtable,
                  const std::shared_ptr<WDbgArkProcess> &process_helper,
                  const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb);
    WDbgArkApiSet() = delete;

    bool IsInited() const { return m_inited; }
    const auto& Get() const { return m_api_sets; }

 private:
    using DataInfo = std::pair<uint64_t, uint32_t>;

    bool Process(WDbgArkMemTableTyped::WalkResult &&walk_result);
    bool ProcessValues(const std::wstring &key, WDbgArkMemTableTyped::WalkResult &&walk_result);
    DataInfo GetDataInfo(ExtRemoteTyped &entry);

 private:
    bool m_inited = false;
    uint32_t m_version = 0;
    uint64_t m_header_offset = 0ULL;
    std::shared_ptr<WDbgArkMemTableTyped> m_memtable{ nullptr };
    std::shared_ptr<WDbgArkProcess> m_process_helper{ nullptr };
    std::shared_ptr<WDbgArkDummyPdb> m_dummy_pdb{ nullptr };

    ApiSets m_api_sets{};

    std::stringstream err{};
};

}   // namespace wa

#endif  // APISETHLP_HPP_
