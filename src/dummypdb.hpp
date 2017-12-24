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

#ifndef DUMMYPDB_HPP_
#define DUMMYPDB_HPP_

#include <engextcpp.hpp>
#include <comip.h>

#include <string>
#include <sstream>
#include <fstream>

#include "manipulators.hpp"

namespace wa {

class WDbgArkDummyPdb {
 public:
    WDbgArkDummyPdb() { m_inited = InitDummyPdbModule(); }

    // symbols should be already unloaded (.reload /u)
    ~WDbgArkDummyPdb() {
        try {
            std::string filename = GetFullPath();
            std::ifstream file(filename);

            if ( file.good() ) {
                file.close();
                std::remove(filename.c_str());
            }
        } catch ( const std::ios_base::failure& ) {}
          catch ( const std::runtime_error& ) {}
    };

    bool IsInited(void) const { return m_inited; }
    std::string GetLongName() const { return m_dummy_pdb_name_long; }
    std::string GetShortName() const { return m_dummy_pdb_name_short; }
    std::string GetFullPath() const { return m_full_path; }
    uint64_t GetModuleBase() const { return m_dummy_pdb_base; }
    uint32_t GetModuleSize() const { return m_dummy_pdb_size; }

    template <class T>
    bool RemoveDummyPdbModule(const T& symbols3_iface) {
        if ( SUCCEEDED(symbols3_iface->GetModuleByModuleName(m_dummy_pdb_name_short.c_str(), 0, nullptr, nullptr)) ) {
            std::string unload_cmd = "/u " + m_dummy_pdb_name_short;

            if ( FAILED(symbols3_iface->Reload(unload_cmd.c_str())) ) {
                return false;
            }
        }

        return true;
    }

 private:
    bool InitDummyPdbModule();

 private:
    bool m_inited = false;
    std::string m_dummy_pdb_name_short{ "dummypdb_" + std::to_string(GetCurrentProcessId()) };
    std::string m_dummy_pdb_name_long{ m_dummy_pdb_name_short + ".pdb" };
    std::string m_drop_path{};
    std::string m_full_path{};
    uint64_t m_dummy_pdb_base = 0xFFFFFFFFFFFF0000;
    uint32_t m_dummy_pdb_size = 0xFFFF;
};

}   // namespace wa

#endif  // DUMMYPDB_HPP_
