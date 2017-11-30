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

#ifndef WHITELIST_HPP_
#define WHITELIST_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <map>
#include <set>
#include <vector>
#include <utility>
#include <memory>

#include "symcache.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// white list range
//////////////////////////////////////////////////////////////////////////
class WDbgArkAnalyzeWhiteList {
 public:
    using Range = std::pair<uint64_t, uint64_t>;                        // start, end
    using Ranges = std::set<Range>;
    using WhiteListEntry = std::vector<std::string>;
    using WhiteListEntries = std::map<std::string, WhiteListEntry>;     // some name : vector of module names

    WDbgArkAnalyzeWhiteList() = delete;
    explicit WDbgArkAnalyzeWhiteList(const std::shared_ptr<WDbgArkSymCache> &sym_cache) : m_sym_cache(sym_cache) {}
    virtual ~WDbgArkAnalyzeWhiteList() {}

    //////////////////////////////////////////////////////////////////////////
    // permanent list
    //////////////////////////////////////////////////////////////////////////
    void AddRangeWhiteList(const uint64_t start, const uint64_t end) {
        AddRangeWhiteListInternal(start, end, &m_ranges);
    }

    void AddRangeWhiteList(const uint64_t start, const uint32_t size) {
        AddRangeWhiteList(start, start + size);
    }

    bool AddRangeWhiteList(const std::string &module_name) {
        return AddRangeWhiteListInternal(module_name, &m_ranges);
    }

    bool AddSymbolWhiteList(const std::string &symbol_name, const uint32_t size) {
        return AddSymbolWhiteListInternal(symbol_name, size, &m_ranges);
    }

    //////////////////////////////////////////////////////////////////////////
    // temp list
    //////////////////////////////////////////////////////////////////////////
    void AddTempRangeWhiteList(const uint64_t start, const uint64_t end) {
        AddRangeWhiteListInternal(start, end, &m_temp_ranges);
    }

    void AddTempRangeWhiteList(const uint64_t start, const uint32_t size) {
        AddTempRangeWhiteList(start, start + size);
    }

    bool AddTempRangeWhiteList(const std::string &module_name) {
        return AddRangeWhiteListInternal(module_name, &m_temp_ranges);
    }

    bool AddTempSymbolWhiteList(const std::string &symbol_name, const uint32_t size) {
        return AddSymbolWhiteListInternal(symbol_name, size, &m_temp_ranges);
    }

    void SetWhiteListEntries(const WhiteListEntries &entries) {
        InvalidateWhiteListEntries();
        m_wl_entries = entries;
    }

    const WhiteListEntries& GetWhiteListEntries(void) const { return m_wl_entries; }

    void AddTempWhiteList(const std::string &name);

    //////////////////////////////////////////////////////////////////////////
    // invalidate lists
    //////////////////////////////////////////////////////////////////////////
    void InvalidateRanges(void) { m_ranges.clear(); }
    void InvalidateTempRanges(void) { m_temp_ranges.clear(); }
    void InvalidateWhiteListEntries(void) { m_wl_entries.clear(); }

    //////////////////////////////////////////////////////////////////////////
    // check
    //////////////////////////////////////////////////////////////////////////
    bool IsAddressInWhiteList(const uint64_t address) const;

 private:
    Ranges m_ranges{};
    Ranges m_temp_ranges{};
    WhiteListEntries m_wl_entries{};
    std::shared_ptr<WDbgArkSymCache> m_sym_cache{};

 private:
    void AddRangeWhiteListInternal(const uint64_t start, const uint64_t end, Ranges* ranges) {
        ranges->insert({ start, end });
    }

    bool AddRangeWhiteListInternal(const std::string &module_name, Ranges* ranges);
    bool AddSymbolWhiteListInternal(const std::string &symbol_name, const uint32_t size, Ranges* ranges);
};

//////////////////////////////////////////////////////////////////////////
// helpers
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeWhiteList::WhiteListEntries GetDriversWhiteList();
WDbgArkAnalyzeWhiteList::WhiteListEntries GetObjectTypesWhiteList();

}   // namespace wa

#endif  // WHITELIST_HPP_
