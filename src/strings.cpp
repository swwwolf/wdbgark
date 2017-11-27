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

#include "strings.hpp"

#include <engextcpp.hpp>

#include <sstream>
#include <utility>
#include <memory>
#include <string>

#include "manipulators.hpp"

namespace wa {

std::wstring string_to_wstring(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

std::string wstring_to_string(const std::wstring& wstr) {
    return std::string(wstr.begin(), wstr.end());
}

std::pair<HRESULT, std::string> UnicodeStringStructToString(const ExtRemoteTyped &unicode_string) {
    std::string output_string("*UNKNOWN*");

    try {
        ExtRemoteTyped loc_unicode_string = unicode_string;
        ExtRemoteTyped buffer = *loc_unicode_string.Field("Buffer");
        const auto len = loc_unicode_string.Field("Length").GetUshort();
        const size_t maxlen = loc_unicode_string.Field("MaximumLength").GetUshort();

        if ( len == 0 && maxlen == 1 ) {
            return std::make_pair(S_OK, output_string);
        }

        if ( maxlen >= sizeof(wchar_t) && (maxlen % sizeof(wchar_t) == 0) ) {
            const size_t max_len_wide = maxlen / sizeof(wchar_t) + 1;

            auto test_name = std::make_unique<wchar_t[]>(max_len_wide);
            const size_t read = buffer.ReadBuffer(test_name.get(), static_cast<ULONG>(maxlen));

            if ( read == maxlen ) {
                output_string = wstring_to_string(test_name.get());
            }

            return std::make_pair(S_OK, output_string);
        }
    } catch ( const ExtRemoteException &Ex ) {
        return std::make_pair(Ex.GetStatus(), output_string);
    }

    return std::make_pair(E_INVALIDARG, output_string);
}

}   // namespace wa
