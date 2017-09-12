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

#include <memory>
#include <string>

#include "memtable.hpp"
#include "symcache.hpp"
#include "manipulators.hpp"

namespace wa {

WDbgArkMemTable::WDbgArkMemTable(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const uint64_t table_start)
    : m_sym_cache(sym_cache),
      m_table_start(table_start) {}

WDbgArkMemTable::WDbgArkMemTable(const std::shared_ptr<WDbgArkSymCache> &sym_cache, const std::string &table_start)
    : WDbgArkMemTable(sym_cache, 0ULL) {
    SetTableStart(table_start);
}

bool WDbgArkMemTable::Walk(WDbgArkMemTable::WalkResult* result) {
    if ( !IsValid() ) {
        return false;
    }

    auto offset = GetTableStart() + GetTableSkipStart();

    try {
        bool terminate = false;

        for ( uint32_t tc = 0; tc < GetTableCount(); tc++ ) {
            for ( uint32_t rc = 0; rc < GetRoutineCount(); rc++ ) {
                ExtRemoteData data(offset + tc * GetRoutineDelta() + rc * g_Ext->m_PtrSize, g_Ext->m_PtrSize);
                auto ptr = data.GetPtr();

                if ( ptr != 0ULL || IsCollectNull() ) {
                    result->push_back(ptr);
                } else if ( IsBreakOnNull() ) {
                    terminate = true;
                    break;
                }
            }

            if ( terminate == true ) {
                break;
            }
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return !result->empty();
}

}   // namespace wa
