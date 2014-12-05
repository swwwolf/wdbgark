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

#include <engextcpp.hpp>
#include <dbghelp.h>
#include "colorhack.hpp"
#include "strings.hpp"

bool WDbgArkColorHack::Init() {
    try {
        HMODULE windbg_module = GetModuleHandle(NULL);

        if ( !windbg_module ) {
            err << __FUNCTION__ << ": GetModuleHandle failed" << endlerr;
            return false;
        }

        PIMAGE_NT_HEADERS nth = ImageNtHeader(windbg_module);

        if ( !nth ) {
            err << __FUNCTION__ << ": can't get NT header" << endlerr;
            return false;
        }

        uintptr_t windbg_module_end = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(windbg_module) +\
            nth->OptionalHeader.SizeOfImage);

        PIMAGE_SECTION_HEADER sech = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(nth) +\
            sizeof(*nth));

        PIMAGE_SECTION_HEADER sech_text = nullptr;
        PIMAGE_SECTION_HEADER sech_data = nullptr;

        for ( int i = 0; i < nth->FileHeader.NumberOfSections; i++ ) {
            if ( _stricmp(reinterpret_cast<char*>(&sech->Name[0]), ".text") == 0 )
                sech_text = sech;

            if ( _stricmp(reinterpret_cast<char*>(&sech->Name[0]), ".data") == 0 )
                sech_data = sech;

            if ( sech_text && sech_data )
                break;

            sech++;
        }

        if ( !sech_text || !sech_data ) {
            err << __FUNCTION__ << ": can't get section header" << endlerr;
            return false;
        }

        uintptr_t* start_data = reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(windbg_module) +\
            sech_data->VirtualAddress);

        uintptr_t* end_data = reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(start_data) +\
            sech_data->Misc.VirtualSize);

        uintptr_t start_text = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(windbg_module) +\
            sech_text->VirtualAddress);

        uintptr_t end_text = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(start_text) +\
            sech_text->Misc.VirtualSize);

        if ( start_data > reinterpret_cast<uintptr_t*>(windbg_module_end)
             ||
             end_data > reinterpret_cast<uintptr_t*>(windbg_module_end)
             ||
             start_text > windbg_module_end
             ||
             end_text > windbg_module_end ) { err << __FUNCTION__ << ": something is wrong" << endlerr; return false; }

        while ( start_data < end_data ) {
            try {
                if ( *start_data >= start_text && *start_data <= end_text ) {
                    if ( _wcsicmp(reinterpret_cast<wchar_t*>(*start_data), L"Background") == 0 )
                        g_ui_colors = reinterpret_cast<UiColor*>(start_data);

                    if ( _wcsicmp(reinterpret_cast<wchar_t*>(*start_data), L"Normal level command window text") == 0 )
                        g_out_mask_ui_colors = reinterpret_cast<UiColor*>(start_data);

                    if ( g_ui_colors && g_out_mask_ui_colors ) {
                        m_inited = true;
                        break;
                    }
                }
            }
            catch( ... ) { }    // continue

            start_data++;
        }
    }
    catch( ... ) {
        err << __FUNCTION__ << ": exception error" << endlerr;
    }

    return m_inited;
}

void WDbgArkColorHack::PrintInternalInfo(void) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return;
    }

    try {
        out << "--------------------------------------------------------------------------" << endlout;

        UiColor* loc_ui_color = g_ui_colors;
        while ( loc_ui_color->description ) {
            out << "Description : " << wstring_to_string(loc_ui_color->description) << endlout;
            out << "DML name    : " << wstring_to_string(loc_ui_color->dml_name) << endlout;
            out << "Colorref    : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->color << endlout;
            out << "Intcolorref : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->internal_color << endlout;
            out << "--------------------------------------------------------------------------" << endlout;

            loc_ui_color++;
        }

        loc_ui_color = g_out_mask_ui_colors;
        while ( loc_ui_color->description ) {
            out << "Description : " << wstring_to_string(loc_ui_color->description) << endlout;
            out << "DML name    : " << wstring_to_string(loc_ui_color->dml_name) << endlout;
            out << "Colorref    : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->color << endlout;
            out << "Intcolorref : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->internal_color << endlout;
            out << "--------------------------------------------------------------------------" << endlout;

            loc_ui_color++;
        }
    }
    catch( ... ) {
        err << __FUNCTION__ << ": exception error" << endlerr;
    }
}
