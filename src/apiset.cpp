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

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"
#include "process.hpp"
#include "memtable.hpp"
#include "apisethlp.hpp"
#include "bproxy.hpp"

namespace wa {

void DisplayApiSetTable(const WDbgArkApiSet::ApiSets &table);

EXT_COMMAND(wa_apiset,
            "Output user-mode and/or kernel-mode ApiSet map",
            "{process;e64,o;process;Process address}") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    if ( m_system_ver->GetStrictVer() <= VISTA_SP2_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    try {
        uint64_t offset = 0;

        // kernel-mode
        out << wa::showplus << "Displaying kernel mode nt!MiApiSetSchema" << endlout;

        if ( m_system_ver->GetStrictVer() >= W8RTM_VER ) {
            if ( m_sym_cache->GetSymbolOffset("nt!MiApiSetSchema", true, &offset) ) {
                out << wa::showplus << "nt!MiApiSetSchema pointer: " << std::hex << std::showbase << offset << endlout;

                offset = ExtRemoteData(offset, m_PtrSize).GetPtr();
                out << wa::showplus << "nt!MiApiSetSchema: " << std::hex << std::showbase << offset << endlout;

                WalkApiSetTable(offset, nullptr);
            } else {
                err << wa::showminus << __FUNCTION__ << ": failed to find nt!MiApiSetSchema" << endlerr;
            }
        } else {
            out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        }

        // user-mode
        out << wa::showplus << "Displaying user mode ApiSetSchema" << endlout;

        auto process_helper = std::make_shared<WDbgArkProcess>(m_sym_cache, m_dummy_pdb);

        if ( !process_helper->IsInited() ) {
            err << wa::showminus << __FUNCTION__ << ": failed to init process helper" << endlerr;
            return;
        }

        WDbgArkRemoteTypedProcess set_eprocess(m_sym_cache);

        if ( HasArg("process") ) {
            const std::string proc("nt!_EPROCESS");
            set_eprocess.Set(proc.c_str(), GetArgU64("process"), false, m_sym_cache->GetCookieCache(proc), nullptr);
        } else {
            set_eprocess = process_helper->FindProcessAnyApiSetMap();
        }

        out << wa::showplus << "Process: " << std::hex << std::showbase << set_eprocess.GetDataOffset();
        out << endlout;

        std::string process_name;

        if ( set_eprocess.GetProcessImageFileName(&process_name) ) {
            out << wa::showplus << "Process name: " << process_name << endlout;
        }

        if ( FAILED(set_eprocess.SetImplicitProcess()) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to set process" << endlerr;
            return;
        }

        offset = set_eprocess.GetProcessApiSetMap();

        if ( !offset ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get process ApiSetMap offset" << endlerr;
            return;
        }

        out << wa::showplus << "Process ApiSet map: " << std::hex << std::showbase << offset << endlout;

        WalkApiSetTable(offset, process_helper);
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch ( const ExtInterruptException& ) {
        throw;
    }
}

void WDbgArk::WalkApiSetTable(const uint64_t header_offset, const std::shared_ptr<WDbgArkProcess> &process_helper) {
    try {
        const auto apiset_namespace = m_dummy_pdb->GetShortName() + "!" + GetApiSetNamespace();
        ExtRemoteTyped apiset_header(apiset_namespace.c_str(),
                                     header_offset,
                                     false,
                                     m_sym_cache->GetCookieCache(apiset_namespace),
                                     nullptr);

        const auto version = apiset_header.Field("Version").GetUlong();

        out << wa::showplus << "ApiSet version: " << std::hex << std::showbase << version << endlout;

        uint64_t table_start = 0ULL;

        if ( version == API_SET_VERSION_W7 || version == API_SET_VERSION_W81 ) {
            table_start = apiset_header.Field("Array").m_Offset;
        } else {
            table_start = apiset_header.m_Offset + apiset_header.Field("EntryOffset").GetUlong();
        }

        auto apiset_namespace_entry = m_dummy_pdb->GetShortName() + "!" + GetApiSetNamespaceEntry();
        auto table = std::make_shared<WDbgArkMemTableTyped>(m_sym_cache, table_start, apiset_namespace_entry);

        if ( !table->IsValid() ) {
            err << wa::showminus << __FUNCTION__ << ": invalid table" << endlerr;
            return;
        }

        const auto count = apiset_header.Field("Count").GetUlong();
        out << wa::showplus << "ApiSet count: " << std::hex << std::showbase << count << endlout;

        table->SetTableCount(count);

        auto apiset_helper = std::make_unique<WDbgArkApiSet>(apiset_header,
                                                             table,
                                                             process_helper,
                                                             m_dummy_pdb,
                                                             m_sym_cache);

        if ( !apiset_helper->IsInited() ) {
            err << wa::showminus << __FUNCTION__ << ": ApiSet helper" << endlerr;
            return;
        }

        DisplayApiSetTable(apiset_helper->Get());
    } catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
}

void DisplayApiSetTable(const WDbgArkApiSet::ApiSets &table) {
    auto tp = std::make_unique<WDbgArkBPProxy<wchar_t>>();

    // 180
    tp->AddColumn(L"#", 5);
    tp->AddColumn(L"Name", 85);
    tp->AddColumn(L"Hosts", 85);
    tp->AddColumn(L"Flags", 5);

    tp->PrintHeader();

    size_t i = 0;

    for ( const auto [name, hosts] : table ) {
        std::wstring hosts_result{};

        for ( const auto host : hosts ) {
            hosts_result += host + L" ";
        }

        if ( !hosts_result.empty() ) {
            hosts_result = hosts_result.substr(0, hosts_result.size() - 1);
        }

        std::wstringstream hex_str;
        hex_str << std::hex << i;

        *tp << hex_str.str() << name << hosts_result << 0;
        tp->FlushOut();
        tp->PrintFooter();

        i++;
    }

    tp->PrintFooter();
}

}   // namespace wa
