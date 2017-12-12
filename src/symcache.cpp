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

#include "symcache.hpp"

#include <engextcpp.hpp>

#include <string>
#include <map>
#include <mutex>
#include <iostream>

namespace wa {

bool WDbgArkSymCache::GetSymbolOffset(const std::string &symbol_name, const bool ret_zero, uint64_t* offset) {
    *offset = 0ULL;

    try {
        *offset = m_sym_cache.at(symbol_name);
        return true;
    } catch ( const std::out_of_range& ) {
        __noop;
    }

    // not found in cache
    const auto result = g_Ext->GetSymbolOffset(symbol_name.c_str(), ret_zero, offset);    // may throw

    if ( result == true ) {
        m_sym_cache[symbol_name] = *offset;
    }

    return result;
}

uint64_t* WDbgArkSymCache::GetCookieCache(const std::string &symbol_name) {
    return &m_cookie_cache[symbol_name];
}

uint32_t WDbgArkSymCache::GetTypeSize(const std::string &type) {
    try {
        return m_type_size_cache.at(type);
    } catch ( const std::out_of_range& ) {
        __noop;
    }

    const auto type_size = ::GetTypeSize(type.c_str());

    // type not found
    if ( !type_size ) {
        return 0UL;
    }

    // not found in cache
    m_type_size_cache[type] = type_size;
    return type_size;
}

}   // namespace wa
