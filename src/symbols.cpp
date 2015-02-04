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

#include "symbols.hpp"

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <memory>

#include "manipulators.hpp"

namespace wa {

bool CheckSymbolsPath(const std::string& test_path, const bool display_error) {
    unsigned __int32  buffer_size = 0;
    bool              result      = false;
    std::stringstream err;

    HRESULT hresult = g_Ext->m_Symbols->GetSymbolPath(nullptr, 0, reinterpret_cast<PULONG>(&buffer_size));

    if ( !SUCCEEDED(hresult) ) {
        err << __FUNCTION__ ": GetSymbolPath failed" << endlerr;
        return false;
    }

    std::unique_ptr<char[]> symbol_path_buffer(new char[buffer_size]);

    hresult = g_Ext->m_Symbols->GetSymbolPath(symbol_path_buffer.get(),
                                              buffer_size,
                                              reinterpret_cast<PULONG>(&buffer_size));

    if ( !SUCCEEDED(hresult) ) {
        err << __FUNCTION__ ": GetSymbolPath failed" << endlerr;
        return false;
    }

    std::string check_path = symbol_path_buffer.get();

    if ( check_path.empty() || check_path == " " ) {
        if ( display_error ) {
            err << __FUNCTION__ << ": seems that your symbol path is empty. Fix it!" << endlerr;
        }
    } else if ( check_path.find(test_path) == std::string::npos ) {
        if ( display_error ) {
            std::stringstream warn;

            warn << __FUNCTION__ << ": seems that your symbol path may be incorrect. ";
            warn << "Include symbol path (" << test_path << ")" << endlwarn;
        }
    } else {
        result = true;
    }

    return result;
}

}   // namespace wa
