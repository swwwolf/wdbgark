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

#include "dummypdb.hpp"

#include <string>
#include <memory>
#include <cstdio>
#include <fstream>

#include "resources.hpp"
#include "manipulators.hpp"
#include "symbols.hpp"

namespace wa {

WDbgArkDummyPdb::WDbgArkDummyPdb() : m_inited(false),
                                     m_dummy_pdb_name_long(),
                                     m_dummy_pdb_name_short(),
                                     m_drop_path(),
                                     out(),
                                     warn(),
                                     err() {
    m_inited = InitDummyPdbModule();
}

WDbgArkDummyPdb::~WDbgArkDummyPdb() {
    /*
    std::string filename = m_drop_path + m_dummy_pdb_name_long;
    std::ifstream file(filename);

    if ( file.good() ) {
        file.close();

        // TODO(swwwolf): doesn't work 'coz WinDBG keeps handle to the file
        if ( std::remove(filename.c_str()) != 0 )
            err << __FUNCTION__ << ": Failed to remove " << filename << endlerr;
    }
    */
}

//////////////////////////////////////////////////////////////////////////
// don't include resource.h
//////////////////////////////////////////////////////////////////////////
#define IDR_RT_RCDATA1 105
#define IDR_RT_RCDATA2 106
//////////////////////////////////////////////////////////////////////////
bool WDbgArkDummyPdb::InitDummyPdbModule(void) {
    char* resource_name = nullptr;

    m_dummy_pdb_name_short = "dummypdb_" + std::to_string(GetCurrentProcessId());
    m_dummy_pdb_name_long = m_dummy_pdb_name_short + ".pdb";

    // it is not possible to remove this fake module on unload
    if ( !RemoveDummyPdbModule() ) {
        err << __FUNCTION__ << ": RemoveDummyPdbModule failed" << endlerr;
        return false;
    }

    if ( g_Ext->IsCurMachine64() )
        resource_name = MAKEINTRESOURCE(IDR_RT_RCDATA2);
    else
        resource_name = MAKEINTRESOURCE(IDR_RT_RCDATA1);

    std::unique_ptr<WDbgArkResHelper> res_helper(new WDbgArkResHelper);

    if ( !res_helper->DropResource(resource_name, "RT_RCDATA", m_dummy_pdb_name_long) ) {
        err << __FUNCTION__ << ": DropResource failed" << endlerr;
        return false;
    }

    m_drop_path = res_helper->GetDropPath();

    if ( !CheckSymbolsPath(m_drop_path, false) ) {
        if ( !SUCCEEDED(g_Ext->m_Symbols->AppendSymbolPath(m_drop_path.c_str())) ) {
            err << __FUNCTION__ << ": AppendSymbolPath failed" << endlerr;
            return false;
        }
    }

    std::string reload_cmd = "/i " + m_dummy_pdb_name_short + "=0xFFFFFFFFFFFFF000,0xFFF";

    if ( !SUCCEEDED(g_Ext->m_Symbols->Reload(reload_cmd.c_str())) ) {
        err << __FUNCTION__ << ": Reload failed" << endlerr;
        return false;
    }

    return true;
}

bool WDbgArkDummyPdb::RemoveDummyPdbModule(void) {
    if ( SUCCEEDED(g_Ext->m_Symbols->GetModuleByModuleName(m_dummy_pdb_name_short.c_str(), 0, nullptr, nullptr)) ) {
        std::string unload_cmd = "/u " + m_dummy_pdb_name_short;

        if ( !SUCCEEDED(g_Ext->m_Symbols->Reload(unload_cmd.c_str())) ) {
            err << __FUNCTION__ << ": Failed to unload " << m_dummy_pdb_name_short << " module" << endlerr;
            return false;
        }
    }

    return true;
}

}   // namespace wa
