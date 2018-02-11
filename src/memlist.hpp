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

#ifndef SRC_MEMLIST_HPP_
#define SRC_MEMLIST_HPP_

#include <engextcpp.hpp>

#include <memory>
#include <string>
#include <vector>
#include <sstream>

#include "symcache.hpp"
#include "manipulators.hpp"

namespace wa {

class WDbgArkMemList {
 public:
    using WalkResult = std::vector<uint64_t>;

    explicit WDbgArkMemList(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const uint64_t list_head)
        : m_list_head(list_head),
          m_sym_cache(sym_cache) {}

    explicit WDbgArkMemList(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const std::string &list_head)
        : WDbgArkMemList(sym_cache, 0ULL) { SetListHead(list_head); }

    WDbgArkMemList() = delete;

    virtual ~WDbgArkMemList() = default;

    virtual bool IsValid() const { return m_list_head != 0ULL; }

    void SetListHead(const uint64_t list_head) { m_list_head = list_head; }
    void SetListHead(const std::string &list_head) {
        if ( !m_sym_cache->GetSymbolOffset(list_head, true, &m_list_head) ) {
            err << wa::showminus << __FUNCTION__ << ": unable to find " << list_head << endlerr;
        } else {
            m_list_head_name = list_head;
        }
    }

    uint64_t GetListHead() const { return m_list_head; }

    void SetListHeadName(const std::string &name) { m_list_head_name = name; }
    std::string GetListHeadName() const { return m_list_head_name; }

    void SetLinkOffset(const uint32_t offset) { m_link_offset = offset; }
    uint32_t GetLinkOffset() const { return m_link_offset; }

    void SetRoutineDelta(const uint32_t delta) { m_routine_delta = delta; }
    uint32_t GetRoutineDelta() const { return m_routine_delta; }

    void SetIsDouble(const bool flag) { m_doubly_linked = flag; }
    bool IsDouble() const { return m_doubly_linked; }

    void SetCollectNull(const bool flag) { m_collect_null = flag; }
    bool IsCollectNull() const { return m_collect_null; }

    virtual bool WDbgArkMemList::WalkNodes(WalkResult* result) {
        if ( !IsValid() ) {
            return false;
        }

        try {
            ExtRemoteList list_head(GetListHead(), GetLinkOffset(), IsDouble());

            for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
                result->push_back(list_head.GetNodeOffset());
            }
        } catch ( const ExtRemoteException &Ex ) {
            err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        }

        return !result->empty();
    }

    virtual bool WDbgArkMemList::Walk(WalkResult* result) {
        if ( !IsValid() ) {
            return false;
        }

        WalkResult nodes;

        if ( !WalkNodes(&nodes) ) {
            return false;
        }

        result->reserve(nodes.size());

        for ( const auto node : nodes ) {
            try {
                ExtRemoteData data(node + GetRoutineDelta(), g_Ext->m_PtrSize);
                const auto ptr = data.GetPtr();

                if ( ptr != 0ULL || IsCollectNull() ) {
                    result->push_back(ptr);
                }
            } catch ( const ExtRemoteException &Ex ) {
                err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
            }
        }

        return !result->empty();
    }

 protected:
    uint64_t m_list_head = 0ULL;
    std::string m_list_head_name{};
    uint32_t m_link_offset = 0UL;
    uint32_t m_routine_delta = 0UL;
    bool m_doubly_linked = true;
    bool m_collect_null = false;

    std::shared_ptr<WDbgArkSymCache> m_sym_cache{ nullptr };
};

class WDbgArkMemListTyped : public WDbgArkMemList {
 public:
    using WalkResult = std::vector<ExtRemoteTyped>;

    WDbgArkMemListTyped(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                        const uint64_t list_head,
                        const std::string &type) : WDbgArkMemList(sym_cache, list_head) { SetType(type); }

    WDbgArkMemListTyped(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                        const std::string &list_head,
                        const std::string &type) : WDbgArkMemList(sym_cache, list_head) { SetType(type); }

    WDbgArkMemListTyped() = delete;

    bool IsValid() const { return (m_list_head != 0ULL && m_type_size != 0UL); }

    void SetNodeOffset(const uint32_t offset) { m_node_offset = offset; }
    uint32_t GetNodeOffset() const { return m_node_offset; }

    void SetPtrTo(const bool flag) { m_ptr_to = flag; }
    bool GetPtrTo() const { return m_ptr_to; }

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

        WDbgArkMemList::WalkResult nodes;

        if ( !WalkNodes(&nodes) ) {
            return false;
        }

        result->reserve(nodes.size());

        for ( const auto node : nodes ) {
            try {
                result->emplace_back(ExtRemoteTyped(m_type.c_str(),
                                                    node + GetNodeOffset(),
                                                    GetPtrTo(),
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
    uint32_t m_node_offset = 0UL;
    bool m_ptr_to = false;
};

}   // namespace wa

#endif  // SRC_MEMLIST_HPP_
