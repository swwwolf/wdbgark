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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef STRINGS_HPP_
#define STRINGS_HPP_

#include <engextcpp.hpp>
#include <string>
#include <algorithm>

namespace wa {

#define make_string(x) #x

//////////////////////////////////////////////////////////////////////////
// string routines
//////////////////////////////////////////////////////////////////////////
std::wstring string_to_wstring(const std::string& str);
std::string wstring_to_string(const std::wstring& wstr);
std::pair<HRESULT, std::string> UnicodeStringStructToString(const ExtRemoteTyped &unicode_string);

template <class T = char> inline
std::basic_string<T> tolower(const std::basic_string<T> &str) {
    auto s = str;
    std::transform(std::begin(s), std::end(s), std::begin(s), [](T c) {
        return static_cast<T>(std::tolower(c, std::locale()));
    });

    return s;
}

}   // namespace wa

#endif  // STRINGS_HPP_
