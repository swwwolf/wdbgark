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

#ifndef SRC_MEMTABLE_HPP_
#define SRC_MEMTABLE_HPP_

#include <engextcpp.hpp>

#include <memory>
#include <string>
#include <vector>
#include <sstream>

#include "symcache.hpp"
#include "manipulators.hpp"

namespace wa {

class WDbgArkMemTable {
 public:
    using WalkResult = std::vector<uint64_t>;

    explicit WDbgArkMemTable(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const uint64_t table_start);
    explicit WDbgArkMemTable(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const std::string &table_start);
    WDbgArkMemTable() = delete;

    bool Walk(WalkResult* result);

    bool IsValid() const { return m_table_start != 0ULL; }

    void SetTableStart(const uint64_t table_start) { m_table_start = table_start; }
    void SetTableStart(const std::string &table_start) {
        if ( !m_sym_cache->GetSymbolOffset(table_start, true, &m_table_start) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find " << table_start << endlerr;
        }
    }
    uint64_t GetTableStart() const { return m_table_start; }

    void SetTableSkipStart(const uint32_t skip_start) { m_offset_table_skip_start = skip_start; }
    uint32_t GetTableSkipStart() const { return m_offset_table_skip_start; }

    void SetTableCount(const uint32_t count) { m_table_count = count; }
    uint32_t GetTableCount() const { return m_table_count; }

    void SetRoutineDelta(const uint32_t delta) { m_routine_delta = delta; }
    uint32_t GetRoutineDelta() const { return m_routine_delta; }

    void SetBreakOnNull(const bool flag) { m_break_on_null = flag; }
    bool IsBreakOnNull() const { return m_break_on_null; }

    void SetCollectNull(const bool flag) { m_collect_null = flag; }
    bool IsCollectNull() const { return m_collect_null; }

 private:
    uint64_t m_table_start = 0ULL;
    uint32_t m_offset_table_skip_start = 0UL;
    uint32_t m_table_count = 0UL;
    uint32_t m_routine_delta = 0UL;
    bool m_break_on_null = false;
    bool m_collect_null = false;

    std::shared_ptr<WDbgArkSymCache> m_sym_cache{};
    std::stringstream err{};
};

}   // namespace wa

#endif  // SRC_MEMTABLE_HPP_
