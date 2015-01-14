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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef STRINGS_HPP_
#define STRINGS_HPP_

#include <string>
#include <sstream>
#include <utility>

#include <engextcpp.hpp>
#include "manipulators.hpp"

#define make_string(x) #x

//////////////////////////////////////////////////////////////////////////
// string routines
//////////////////////////////////////////////////////////////////////////
std::wstring __forceinline string_to_wstring(const std::string& str) {
    return std::wstring( str.begin(), str.end() );
}

std::string __forceinline wstring_to_string(const std::wstring& wstr) {
    return std::string( wstr.begin(), wstr.end() );
}

static std::pair<HRESULT, std::string> UnicodeStringStructToString(const ExtRemoteTyped &unicode_string) {
    std::string output_string = "";

    try {
        ExtRemoteTyped   loc_unicode_string = unicode_string;
        ExtRemoteTyped   buffer = *loc_unicode_string.Field("Buffer");
        unsigned __int16 len = loc_unicode_string.Field("Length").GetUshort();
        unsigned __int16 maxlen = loc_unicode_string.Field("MaximumLength").GetUshort();

        if ( len == 0 && maxlen == 1 ) {
            return std::make_pair(S_OK, output_string);
        }

        if ( maxlen >= sizeof(wchar_t) && (maxlen % sizeof(wchar_t) == 0) ) {
            unsigned __int16 max_len_wide = maxlen / sizeof(wchar_t) + 1;

            std::unique_ptr<wchar_t[]> test_name(new wchar_t[max_len_wide]);
            std::memset(test_name.get(), 0, max_len_wide * sizeof(wchar_t));

            unsigned __int32 read = buffer.ReadBuffer(test_name.get(), maxlen, true);

            if ( read == maxlen )
                output_string = wstring_to_string(test_name.get());

            return std::make_pair(S_OK, output_string);
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        std::stringstream locerr;

        locerr << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return std::make_pair(Ex.GetStatus(), output_string);
    }

    return std::make_pair(E_INVALIDARG, output_string);
}

#endif  // STRINGS_HPP_
