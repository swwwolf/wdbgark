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

#ifndef MANIPULATORS_HPP_
#define MANIPULATORS_HPP_

#include <engextcpp.hpp>

#include <sstream>
#include <iomanip>
#include <string>
#include <regex>

namespace wa {

template <class T>
struct ManipTraits {};

template <>
struct ManipTraits<char> {
    static auto constexpr p = "[+] ";
    static auto constexpr m = "[-] ";
    static auto constexpr q = "[?] ";

    static auto constexpr nl = "\n";
    static auto constexpr s = "%s";

    static auto constexpr amp = "&";
    static auto constexpr amp_rpl = "&amp;";
    static auto constexpr lt = "<";
    static auto constexpr lt_rpl = "&lt;";
    static auto constexpr gt = ">";
    static auto constexpr gt_rpl = "&gt;";
    static auto constexpr quot = "\"";
    static auto constexpr quot_rpl = "&quot;";
};

template <>
struct ManipTraits<wchar_t> {
    static auto constexpr p = L"[+] ";
    static auto constexpr m = L"[-] ";
    static auto constexpr q = L"[?] ";

    static auto constexpr nl = L"\n";
    static auto constexpr s = L"%s";

    static auto constexpr amp = L"&";
    static auto constexpr amp_rpl = L"&amp;";
    static auto constexpr lt = L"<";
    static auto constexpr lt_rpl = L"&lt;";
    static auto constexpr gt = L">";
    static auto constexpr gt_rpl = L"&gt;";
    static auto constexpr quot = L"\"";
    static auto constexpr quot_rpl = L"&quot;";
};

template <class T = char>
inline std::basic_ostream<T>& showplus(std::basic_ostream<T> &arg) {
    arg << ManipTraits<T>::p;
    return arg;
}

template <class T = char>
inline std::basic_ostream<T>& showminus(std::basic_ostream<T> &arg) {
    arg << ManipTraits<T>::m;
    return arg;
}

template <class T = char>
inline std::basic_ostream<T>& showqmark(std::basic_ostream<T> &arg) {
    arg << ManipTraits<T>::q;
    return arg;
}

template <class T = char>
inline std::basic_ostream<T>& endlout(std::basic_ostream<T> &arg) {
    std::basic_stringstream<T> ss;

    arg << ManipTraits<T>::nl;
    ss << arg.rdbuf();
    g_Ext->Dml(ManipTraits<T>::s, ss.str().c_str());
    return arg.flush();
}

template <class T = char>
inline std::basic_ostream<T>& endlwarn(std::basic_ostream<T> &arg) {
    std::basic_stringstream<T> ss;

    arg << ManipTraits<T>::nl;
    ss << arg.rdbuf();
    g_Ext->DmlWarn(ManipTraits<T>::s, ss.str().c_str());
    return arg.flush();
}

template <class T = char>
inline std::basic_ostream<T>& endlerr(std::basic_ostream<T> &arg) {
    std::basic_stringstream<T> ss;

    arg << ManipTraits<T>::nl;
    ss << arg.rdbuf();
    g_Ext->DmlErr(ManipTraits<T>::s, ss.str().c_str());
    return arg.flush();
}

template <class T = char>
inline std::basic_string<T> normalize_special_chars(const std::basic_string<T> &s) {
    std::basic_regex<T> regex_amp(ManipTraits<T>::amp);
    std::basic_string<T> out = std::regex_replace(s, regex_amp, ManipTraits<T>::amp_rpl);

    std::basic_regex<T> regex_lt(ManipTraits<T>::lt);
    out = std::regex_replace(out, regex_lt, ManipTraits<T>::lt_rpl);

    std::basic_regex<T> regex_gt(ManipTraits<T>::gt);
    out = std::regex_replace(out, regex_gt, ManipTraits<T>::gt_rpl);

    std::basic_regex<T> regex_quot(ManipTraits<T>::quot);
    out = std::regex_replace(out, regex_quot, ManipTraits<T>::quot_rpl);

    return out;
}

}   // namespace wa

#endif  // MANIPULATORS_HPP_
