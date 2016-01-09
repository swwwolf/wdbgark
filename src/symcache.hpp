/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2015  Vyacheslav Rusakoff
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
#include <map>
#include <mutex>

namespace wa {
//////////////////////////////////////////////////////////////////////////
// symbols cache class
//////////////////////////////////////////////////////////////////////////
class WDbgArkSymCache {
 public:
    WDbgArkSymCache() : m_cache() {}

    bool GetSymbolOffset(const std::string &symbol_name, const bool ret_zero, uint64_t* offset);
    void Invalidate(void) { m_cache.clear(); }

 private:
     using SymbolCache = std::map<std::string, uint64_t>;   // symbol name : address

     SymbolCache m_cache;
};

}   // namespace wa

#endif  // SYMCACHE_HPP_
