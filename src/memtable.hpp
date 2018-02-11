/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2018  Vyacheslav Rusakoff
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

    explicit WDbgArkMemTable(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const uint64_t table_start)
        : m_table_start(table_start),
          m_sym_cache(sym_cache) {}

    explicit WDbgArkMemTable(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const std::string &table_start)
        : WDbgArkMemTable(sym_cache, 0ULL) { SetTableStart(table_start); }

    WDbgArkMemTable() = delete;

    virtual ~WDbgArkMemTable() = default;

    virtual bool IsValid() const { return m_table_start != 0ULL; }

    void SetTableStart(const uint64_t table_start) { m_table_start = table_start; }
    void SetTableStart(const std::string &table_start) {
        if ( !m_sym_cache->GetSymbolOffset(table_start, true, &m_table_start) ) {
            err << wa::showminus << __FUNCTION__ << ": unable to find " << table_start << endlerr;
        } else {
            m_table_name = table_start;
        }
    }

    uint64_t GetTableStart() const { return m_table_start; }

    void SetTableName(const std::string &name) { m_table_name = name; }
    std::string GetTableName() const { return m_table_name; }

    void SetTableSkipStart(const uint32_t skip_start) { m_offset_table_skip_start = skip_start; }
    uint32_t GetTableSkipStart() const { return m_offset_table_skip_start; }

    void SetTableCount(const uint32_t count) { m_table_count = count; }
    uint32_t GetTableCount() const { return m_table_count; }

    void SetRoutineDelta(const uint32_t delta) { m_routine_delta = delta; }
    uint32_t GetRoutineDelta() const { return m_routine_delta; }

    void SetRoutineCount(const uint32_t count) { m_routine_count = count; }
    uint32_t GetRoutineCount() const { return m_routine_count; }

    void SetBreakOnNull(const bool flag) { m_break_on_null = flag; }
    bool IsBreakOnNull() const { return m_break_on_null; }

    void SetCollectNull(const bool flag) { m_collect_null = flag; }
    bool IsCollectNull() const { return m_collect_null; }

    virtual bool WDbgArkMemTable::Walk(WalkResult* result) {
        if ( !IsValid() ) {
            return false;
        }

        result->reserve(static_cast<size_t>(GetTableCount()) * static_cast<size_t>(GetRoutineCount()));

        const auto offset = GetTableStart() + GetTableSkipStart();

        bool terminate = false;

        for ( uint32_t tc = 0; tc < GetTableCount(); tc++ ) {
            for ( uint32_t rc = 0; rc < GetRoutineCount(); rc++ ) {
                try {
                    ExtRemoteData data(offset + tc * GetRoutineDelta() + rc * g_Ext->m_PtrSize, g_Ext->m_PtrSize);
                    const auto ptr = data.GetPtr();

                    if ( ptr != 0ULL || IsCollectNull() ) {
                        result->push_back(ptr);
                    } else if ( IsBreakOnNull() ) {
                        terminate = true;
                        break;
                    }
                } catch ( const ExtRemoteException &Ex ) {
                    err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
                }
            }

            if ( terminate == true ) {
                break;
            }
        }

        return !result->empty();
    }

 protected:
    uint64_t m_table_start = 0ULL;
    std::string m_table_name{};
    uint32_t m_offset_table_skip_start = 0UL;
    uint32_t m_table_count = 0UL;
    uint32_t m_routine_delta = 0UL;
    uint32_t m_routine_count = 1;
    bool m_break_on_null = false;
    bool m_collect_null = false;

    std::shared_ptr<WDbgArkSymCache> m_sym_cache{ nullptr };
};

class WDbgArkMemTableTyped : public WDbgArkMemTable {
 public:
    using WalkResult = std::vector<ExtRemoteTyped>;

    WDbgArkMemTableTyped(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                         const uint64_t table_start,
                         const std::string &type) : WDbgArkMemTable(sym_cache, table_start) { SetType(type); }

    WDbgArkMemTableTyped(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                         const std::string &table_start,
                         const std::string &type) : WDbgArkMemTable(sym_cache, table_start) { SetType(type); }

    WDbgArkMemTableTyped() = delete;

    bool IsValid() const { return (m_table_start != 0ULL && m_type_size != 0UL); }

    void SetType(const std::string &type) {
        m_type_size = m_sym_cache->GetTypeSize(type.c_str());

        if ( m_type_size != 0UL ) {
            m_type = type;
        }
    }

    std::string GetType() const { return m_type; }
    uint32_t GetTypeSize() const { return m_type_size; }

    bool Walk(WalkResult* result) {
        if ( !IsValid() ) {
            return false;
        }

        result->reserve(static_cast<size_t>(GetTableCount()));

        const auto offset = GetTableStart() + GetTableSkipStart();

        for ( uint32_t tc = 0; tc < GetTableCount(); tc++ ) {
            try {
                result->emplace_back(ExtRemoteTyped(m_type.c_str(),
                                                    offset + tc * m_type_size,
                                                    false,
                                                    m_sym_cache->GetCookieCache(m_type),
                                                    nullptr));
            } catch ( const ExtRemoteException &Ex ) {
                err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
            }
        }

        return !result->empty();
    }

 private:
    std::string m_type{};
    uint32_t m_type_size = 0UL;
};

}   // namespace wa

#endif  // SRC_MEMTABLE_HPP_
