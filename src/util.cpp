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

#include "util.hpp"
#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <algorithm>

#include "manipulators.hpp"

namespace wa {

bool NormalizeAddress(const uint64_t address, uint64_t* result) {
    std::stringstream string_value;
    string_value << std::hex << std::showbase << address;

    try {
        *result = g_Ext->EvalExprU64(string_value.str().c_str());
        return true;
    } catch ( const ExtStatusException &Ex ) {
        std::stringstream err;
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    *result = 0ULL;
    return false;
}

bool IsLiveKernel() {
    return ((g_Ext->m_DebuggeeClass == DEBUG_CLASS_KERNEL) && (g_Ext->m_DebuggeeQual == DEBUG_KERNEL_CONNECTION));
}

void WaitForGoInput() {
    while ( true ) {
        char buffer[3] = { 0 };
        auto result = g_Ext->m_Control->Input(buffer, sizeof(buffer), nullptr);

        if ( !SUCCEEDED(result) ) {
            continue;
        }

        std::string check_go(buffer);
        std::transform(std::begin(check_go),
                       std::end(check_go),
                       std::begin(check_go),
                       [](char c) {return static_cast<char>(tolower(c)); });

        if ( check_go == "g" || check_go == "go" ) {
            break;
        }
    }
}

}   // namespace wa
