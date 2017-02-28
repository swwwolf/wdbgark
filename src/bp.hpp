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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef SRC_BP_HPP_
#define SRC_BP_HPP_

#include <engextcpp.hpp>

#include <cstdint>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <memory>
#include <mutex>

#include "symcache.hpp"
#include "objhelper.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// breakpoint helper class
//////////////////////////////////////////////////////////////////////////
class WDbgArkBP {
 public:
    using Breakpoints = std::map<uint32_t, IDebugBreakpoint*>;
    using BPList = std::vector<uint64_t>;       // vector of offsets
    using BPIdList = std::vector<uint32_t>;     // vector of IDs

    explicit WDbgArkBP(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    WDbgArkBP() = delete;
    virtual ~WDbgArkBP();

    bool IsInited() const { return m_inited; }
    bool IsKnownBp(const uint32_t id);
    bool IsKnownBp(const IDebugBreakpoint* bp);
    void Invalidate();

    HRESULT Add(const uint64_t offset, uint32_t* id);
    void Add(const BPList &bp_list, BPIdList* id_list);
    HRESULT Add(const std::string &expression, uint32_t* id);
    HRESULT Add(const ExtRemoteTyped &object, BPIdList* id_list);  // device or driver
    HRESULT Remove(const uint32_t id);
    void Remove(const BPIdList &id_list);

 private:
    HRESULT Add(const uint64_t offset, const std::string &expression, uint32_t* id);

 private:
    bool m_inited = false;
    std::mutex m_mutex{};
    Breakpoints m_bp{};
    std::shared_ptr<WDbgArkSymCache> m_sym_cache{};
    std::unique_ptr<WDbgArkObjHelper> m_obj_helper{};
    std::stringstream err{};
    std::stringstream warn{};
};

}   // namespace wa

#endif  // SRC_BP_HPP_
