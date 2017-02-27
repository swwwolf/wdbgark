/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2016  Vyacheslav Rusakoff
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

#include "dummypdb.hpp"

#include <string>
#include <memory>
#include <cstdio>
#include <fstream>

#include "resources.hpp"
#include "manipulators.hpp"
#include "symbols.hpp"

namespace wa {

//////////////////////////////////////////////////////////////////////////
// don't include resource.h
//////////////////////////////////////////////////////////////////////////
#define IDR_RT_RCDATA1 105
#define IDR_RT_RCDATA2 106

//////////////////////////////////////////////////////////////////////////
bool WDbgArkDummyPdb::InitDummyPdbModule(void) {
    // it is not possible to remove this fake module on unload
    if ( !RemoveDummyPdbModule(g_Ext->m_Symbols3) ) {
        err << wa::showminus << __FUNCTION__ << ": RemoveDummyPdbModule failed" << endlerr;
        return false;
    }

    char* resource_name = nullptr;

    if ( g_Ext->IsCurMachine64() ) {
        resource_name = MAKEINTRESOURCE(IDR_RT_RCDATA2);
    } else {
        resource_name = MAKEINTRESOURCE(IDR_RT_RCDATA1);
    }

    auto res_helper = std::make_unique<WDbgArkResHelper>();

    if ( !res_helper->DropResource(resource_name, "RT_RCDATA", m_dummy_pdb_name_long) ) {
        err << wa::showminus << __FUNCTION__ << ": DropResource failed" << endlerr;
        return false;
    }

    m_drop_path = res_helper->GetDropPath();

    WDbgArkSymbolsBase symbols_base;

    if ( !symbols_base.CheckSymbolsPath(false, m_drop_path) ) {
        if ( !SUCCEEDED(symbols_base.AppendSymbolPath(m_drop_path)) ) {
            err << wa::showminus << __FUNCTION__ << ": AppendSymbolPath failed" << endlerr;
            return false;
        }
    }

    std::stringstream reload_cmd;
    reload_cmd << "/i " << m_dummy_pdb_name_short << "=" << std::hex << std::showbase << m_dummy_pdb_base;
    reload_cmd << "," << std::hex << std::showbase << m_dummy_pdb_size;

    if ( !SUCCEEDED(g_Ext->m_Symbols->Reload(reload_cmd.str().c_str())) ) {
        err << wa::showminus << __FUNCTION__ << ": Reload failed" << endlerr;
        return false;
    }

    m_full_path = m_drop_path + m_dummy_pdb_name_long;
    return true;
}

bool WDbgArkDummyPdb::RemoveDummyPdbModule(const ExtCheckedPointer<IDebugSymbols3> &symbols3_iface) {
    if ( SUCCEEDED(symbols3_iface->GetModuleByModuleName(m_dummy_pdb_name_short.c_str(), 0, nullptr, nullptr)) ) {
        std::string unload_cmd = "/u " + m_dummy_pdb_name_short;

        if ( !SUCCEEDED(symbols3_iface->Reload(unload_cmd.c_str())) ) {
            return false;
        }
    }

    return true;
}

}   // namespace wa
