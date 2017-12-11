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

#ifndef SYMCACHE_HPP_
#define SYMCACHE_HPP_

#include <string>
#include <unordered_map>

namespace wa {
//////////////////////////////////////////////////////////////////////////
// symbols cache class
//////////////////////////////////////////////////////////////////////////
class WDbgArkSymCache {
 public:
    void Invalidate(void) { m_sym_cache.clear(); }

    bool GetSymbolOffset(const std::string &symbol_name, const bool ret_zero, uint64_t* offset);
    uint64_t* GetCookieCache(const std::string &symbol_name);
    uint32_t GetTypeSize(const std::string &type);

 private:
     using SymbolCache = std::unordered_map<std::string, uint64_t>;     // symbol name : address
     using CookieCache = std::unordered_map<std::string, uint64_t>;     // symbol name : cookie
     using TypeSizeCache = std::unordered_map<std::string, uint32_t>;   // symbol name : type

     SymbolCache m_sym_cache{};
     CookieCache m_cookie_cache{};
     TypeSizeCache m_type_size_cache{};
};

}   // namespace wa

#endif  // SYMCACHE_HPP_
