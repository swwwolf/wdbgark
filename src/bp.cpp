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

#include <engextcpp.hpp>

#include <map>
#include <string>
#include <algorithm>
#include <mutex>

#include "bp.hpp"
#include "manipulators.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
WDbgArkBP::WDbgArkBP(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : m_sym_cache(sym_cache),
      m_obj_helper(std::make_unique<WDbgArkObjHelper>(sym_cache)) {
    if ( !m_obj_helper->IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": failed to initialize WDbgArkObjHelper" << endlerr;
        return;
    }

    m_inited = true;
}

WDbgArkBP::~WDbgArkBP() {
    Invalidate();
}

bool WDbgArkBP::IsKnownBp(const uint32_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if ( m_bp.empty() )
        return false;

    try {
        m_bp.at(id);
        return true;
    } catch ( const std::out_of_range& ) {}

    return false;
}

bool WDbgArkBP::IsKnownBp(const IDebugBreakpoint* bp) {
    uint32_t id = 0;
    HRESULT result = const_cast<IDebugBreakpoint*>(bp)->GetId(reinterpret_cast<PULONG>(&id));

    if ( SUCCEEDED(result) )
        return IsKnownBp(id);

    return false;
}

void WDbgArkBP::Invalidate() {
    std::lock_guard<std::mutex> lock(m_mutex);

    for_each(m_bp.begin(), m_bp.end(), [](Breakpoints::value_type &bp) {
        g_Ext->m_Control->RemoveBreakpoint(bp.second); });

    m_bp.clear();
}

HRESULT WDbgArkBP::Add(const uint64_t offset, uint32_t* id) {
    return Add(offset, std::string(), id);
}

void WDbgArkBP::Add(const BPList &bp_list, BPIdList* id_list) {
    for ( auto &offset : bp_list ) {
        uint32_t id = 0;
        HRESULT result = Add(offset, &id);

        if ( SUCCEEDED(result) )
            id_list->push_back(id);
    }
}

HRESULT WDbgArkBP::Add(const std::string &expression, uint32_t* id) {
    return Add(0, expression, id);
}

HRESULT WDbgArkBP::Add(const ExtRemoteTyped &object, BPIdList* id_list) {
    auto result = m_obj_helper->GetObjectTypeName(object);

    if ( FAILED(result.first) ) {
        err << wa::showminus << __FUNCTION__ ": GetObjectTypeName failed" << endlerr;
        return result.first;
    }

    auto type_name = result.second;

    if ( type_name != "Device" && type_name != "Driver" ) {
        err << wa::showminus << __FUNCTION__ ": unsupported object type " << type_name << endlerr;
        return E_NOTIMPL;
    }

    ExtRemoteTyped driver;

    if ( type_name == "Device" )
        driver = *const_cast<ExtRemoteTyped&>(object).Field("DriverObject");
    else
        driver = object;

    auto major_table = WDbgArkDrvObjHelper(m_sym_cache, driver).GetMajorTable();

    if ( major_table.empty() ) {
        err << wa::showminus << __FUNCTION__ ": empty major table" << endlerr;
        return E_UNEXPECTED;
    }

    uint64_t offset = 0;
    if ( !m_sym_cache->GetSymbolOffset("nt!IopInvalidDeviceRequest", true, &offset) )
        warn << wa::showqmark << __FUNCTION__ ": nt!IopInvalidDeviceRequest not found" << endlwarn;

    BPList bp_list;
    for ( auto &entry : major_table ) {
        if ( entry.first && entry.first != offset )
            bp_list.push_back(entry.first);
    }

    Add(bp_list, id_list);
    return S_OK;
}

HRESULT WDbgArkBP::Remove(const uint32_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);

    HRESULT result = E_UNEXPECTED;

    try {
        auto bp = m_bp.at(id);
        m_bp.erase(id);
        result = g_Ext->m_Control->RemoveBreakpoint(bp);
    } catch (const std::out_of_range&) {}

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to remove breakpoint using id ";
        err << std::hex << std::showbase << id << endlerr;
    }

    return result;
}

void WDbgArkBP::Remove(const BPIdList &id_list) {
    for ( auto &id : id_list ) {
        Remove(id);
    }
}

HRESULT WDbgArkBP::Add(const uint64_t offset, const std::string &expression, uint32_t* id) {
    std::lock_guard<std::mutex> lock(m_mutex);

    IDebugBreakpoint* bp = nullptr;
    HRESULT result = g_Ext->m_Control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to add breakpoint" << endlerr;
        return result;
    }

    result = bp->SetFlags(DEBUG_BREAKPOINT_GO_ONLY | DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY);

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to enable breakpoint flags" << endlerr;
        g_Ext->m_Control->RemoveBreakpoint(bp);
        return result;
    }

    if ( expression.empty() )
        result = bp->SetOffset(offset);
    else
        result = bp->SetOffsetExpression(expression.c_str());

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to set breakpoint offset to ";

        if ( expression.empty() )
            err << std::hex << std::showbase << offset << endlerr;
        else
            err << expression << endlerr;

        g_Ext->m_Control->RemoveBreakpoint(bp);
        return result;
    }

    uint32_t bp_id = 0;
    result = bp->GetId(reinterpret_cast<PULONG>(&bp_id));

    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get breakpoint id" << endlerr;
        g_Ext->m_Control->RemoveBreakpoint(bp);
        return result;
    }

    m_bp.insert({ bp_id, bp });
    *id = bp_id;
    return S_OK;
}
//////////////////////////////////////////////////////////////////////////
}   // namespace wa
