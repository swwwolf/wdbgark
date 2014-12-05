/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2014  Vyacheslav Rusakoff
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

#ifndef COLORHACK_HPP_
#define COLORHACK_HPP_

#include <windows.h>
#include <sstream>
using namespace std;

//////////////////////////////////////////////////////////////////////////
// hack WinDbg colors
//////////////////////////////////////////////////////////////////////////
class WDbgArkColorHack {
 public:
    //////////////////////////////////////////////////////////////////////////
    // WinDbg internal structure
    //////////////////////////////////////////////////////////////////////////
    typedef struct UiColorTag {
        wchar_t* description;
        wchar_t* dml_name;
        COLORREF color;
        COLORREF internal_color;
        void*    reserved1;
        void*    reserved2;
    } UiColor;

    WDbgArkColorHack() :
        m_inited(false),
        g_ui_colors(nullptr),
        g_out_mask_ui_colors(nullptr) { }

    ~WDbgArkColorHack() {
        g_out_mask_ui_colors = nullptr;
        g_ui_colors = nullptr;
    }

    bool IsInited(void) const { return m_inited; }
    bool Init(void);
    void PrintInternalInfo(void);

 private:
    bool     m_inited;
    UiColor* g_ui_colors;
    UiColor* g_out_mask_ui_colors;

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

#endif  // COLORHACK_HPP_
