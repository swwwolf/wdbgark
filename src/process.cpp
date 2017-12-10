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

#include <string>
#include <vector>
#include <algorithm>
#include <memory>

#include "process.hpp"
#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "apisethlp.hpp"
#include "processhlp.hpp"

namespace wa {

WDbgArkProcess::WDbgArkProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache) : m_sym_cache(sym_cache) {
    auto list_head = ExtNtOsInformation::GetKernelProcessList();

    m_process_list.reserve(100);

    for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
        try {
            m_process_list.emplace_back(WDbgArkRemoteTypedProcess(m_sym_cache, list_head.GetTypedNode()));
        } catch ( const ExtRemoteException& ) {
            __noop;
        }
    }

    if ( !m_process_list.empty() ) {
        m_inited = true;
    }
}

WDbgArkProcess::WDbgArkProcess(const std::shared_ptr<WDbgArkSymCache> &sym_cache,
                               const std::shared_ptr<WDbgArkDummyPdb> &dummy_pdb) : WDbgArkProcess(sym_cache) {
    m_dummy_pdb = dummy_pdb;

    for ( auto& process : m_process_list ) {
        process.SetDummyPdb(m_dummy_pdb);
    }
}

WDbgArkRemoteTypedProcess WDbgArkProcess::FindProcessByImageFileName(const std::string &process_name) {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return WDbgArkRemoteTypedProcess(m_sym_cache);
    }

    WDbgArkRemoteTypedProcess process(m_sym_cache);
    FindProcessByImageFileName(process_name, &process);

    return process;
}

WDbgArkRemoteTypedProcess WDbgArkProcess::FindProcessAnyGUIProcess() {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return WDbgArkRemoteTypedProcess(m_sym_cache);
    }

    try {
        const auto it = std::find_if(std::begin(m_process_list),
                                     std::end(m_process_list),
                                     [](WDbgArkRemoteTypedProcess &process) {
            return (process.Field("Win32Process").GetPtr() != 0ULL);
        });

        if ( it != std::end(m_process_list) ) {
            return (*it);
        }
    }
    catch( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return WDbgArkRemoteTypedProcess(m_sym_cache);
}

WDbgArkRemoteTypedProcess WDbgArkProcess::FindProcessAnyApiSetMap() {
    if ( !IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": class is not initialized" << endlerr;
        return WDbgArkRemoteTypedProcess(m_sym_cache);
    }

    // we capture by value because we want to revert process on object destruction
    const auto it = std::find_if(std::begin(m_process_list),
                                 std::end(m_process_list),
                                 [this](WDbgArkRemoteTypedProcess process) {
        try {
            if ( FAILED(process.SetImplicitProcess()) ) {
                return false;
            }

            const auto offset = process.GetProcessApiSetMap();

            if ( !offset ) {
                return false;
            }

            // check that ApiSetMap is not paged out
            const auto api_set_namespace = m_dummy_pdb->GetShortName() + "!" + GetApiSetNamespace();
            ExtRemoteTyped apiset_header(api_set_namespace.c_str(),
                                         offset,
                                         false,
                                         m_sym_cache->GetCookieCache(api_set_namespace),
                                         nullptr);

            size_t apiset_size = 0;

            if ( apiset_header.HasField("Size") ) {
                apiset_size = apiset_header.Field("Size").GetUlong();
            } else {
                apiset_size = PAGE_SIZE;
            }

            auto buffer = std::make_unique<uint8_t[]>(apiset_size);
            ExtRemoteData(offset, static_cast<uint32_t>(apiset_size)).ReadBuffer(buffer.get(),
                                                                                 static_cast<uint32_t>(apiset_size));

            return true;
        } catch ( const ExtRemoteException& ) {
            __noop;
        }

        return false;
    });

    if ( it != std::end(m_process_list) ) {
        return (*it);
    }

    return WDbgArkRemoteTypedProcess(m_sym_cache);
}

bool WDbgArkProcess::FindProcessByImageFileName(const std::string &process_name, WDbgArkRemoteTypedProcess* process) {
    auto compare_with = wa::tolower(process_name);

    try {
        const auto it = std::find_if(std::begin(m_process_list),
                                     std::end(m_process_list),
                                     [&compare_with](WDbgArkRemoteTypedProcess &process) {
            std::string image_name{};
            if ( !process.GetProcessImageFileName(&image_name) ) {
                return false;
            }

            image_name = wa::tolower(image_name);

            return (image_name == compare_with);
        });

        if ( it != std::end(m_process_list) ) {
            *process = (*it);
            return true;
        }
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return false;
}

}   // namespace wa
