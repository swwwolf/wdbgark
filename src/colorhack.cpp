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

/*

//////////////////////////////////////////////////////////////////////////
.data:00446280 ; struct UiColor * g_UiColors
.data:00446280 ?g_UiColors@@3PAUUiColor@@A dd offset aBackground
.data:00446280                                         ; DATA XREF: DlgProc_Options(HWND__ *,uint,uint,long)+4C6o
.data:00446280                                         ; InitUiColors(void):loc_43F26Dr ...
.data:00446280                                         ; "Background"
.data:00446284 off_446284      dd offset aWbg          ; DATA XREF: GetUiColorByKeyword(ushort const *):loc_43F33Er
.data:00446284                                         ; "wbg"
.data:00446288 ; LPARAM lParam
.data:00446288 lParam          dd 0                    ; DATA XREF: WinCommandBrowser::OnCreate(void)+196r
.data:00446288                                         ; WinCommand::UpdateColors(void)+Ar ...
.data:0044628C ; int dword_44628C[]
.data:0044628C dword_44628C    dd 0                    ; DATA XREF: InitUiColors(void)+17w
.data:0044628C                                         ; InitUiColors(void)+B1r
.data:00446290                 db    0
.data:00446291                 db    0
.data:00446292                 db    0
.data:00446293                 db    0

...

.data:00446630 ; struct UiColor * g_OutMaskUiColors
.data:00446630 ?g_OutMaskUiColors@@3PAUUiColor@@A dd offset aNormalLevelCom
.data:00446630                                         ; DATA XREF: DlgProc_Options(HWND__ *,uint,uint,long)+548o
.data:00446630                                         ; InitUiColors(void):loc_43F29Br ...
.data:00446630                                         ; "Normal level command window text"
.data:00446634 off_446634      dd offset aNormfg       ; DATA XREF: GetUiColorByKeyword(ushort const *):loc_43F389r
.data:00446634                                         ; "normfg"
.data:00446638 ; int norm_fg_color[]
.data:00446638 norm_fg_color   dd 0                    ; DATA XREF: GetOutMaskUiColors(ulong,ulong *,ulong *):loc_43F48Fr
.data:0044663C ; int dword_44663C[]
.data:0044663C dword_44663C    dd 0                    ; DATA XREF: InitUiColors(void)+FCw
.data:00446640                 dd 0
.data:00446644                 dd 0

...
//////////////////////////////////////////////////////////////////////////

Pseudo code:

//////////////////////////////////////////////////////////////////////////
void __stdcall InitUiColors()
{
  unsigned int v0; // edi@1
  unsigned int v1; // ebx@1
  unsigned int v2; // esi@1
  int v3; // eax@5
  unsigned int i; // esi@5
  COLORREF color; // eax@7
  int v6; // [sp+Ch] [bp-4h]@5

  dword_44628C[0] = GetSysColor(5);
  dword_4462A4 = GetSysColor(8);
  dword_4462BC = GetSysColor(13);
  dword_4462D4 = GetSysColor(14);
  dword_446304 = GetSysColor(14);
  dword_446334 = GetSysColor(14);
  dword_446364 = GetSysColor(8);
  dword_446394 = GetSysColor(15);
  dword_4463C4 = GetSysColor(14);
  dword_4463DC = GetSysColor(5);
  dword_4463F4 = GetSysColor(8);
  dword_44640C = GetSysColor(8);
  dword_446454 = GetSysColor(8);
  dword_446484 = GetSysColor(8);
  dword_4465D4 = GetSysColor(14);
  dword_446604 = GetSysColor(19);
  v0 = 0;
  dword_44661C = GetSysColor(3);
  v1 = 0;
  v2 = 0;
  do
  {
    if ( *(struct UiColor **)((char *)&g_UiColors + v2 * 4) )
      SetUiColor(v1, dword_44628C[v2]);
    v2 += 6;
    ++v1;
  }
  while ( v2 < 0xEA );
  v3 = 0;
  v6 = 0;
  i = 0;
  do
  {
    if ( *(struct UiColor **)((char *)&g_OutMaskUiColors + i * 4) )
    {
      color = GetSysColor((v3 & 1) != 0 ? COLOR_WINDOW : COLOR_WINDOWTEXT);
      dword_44663C[i] = color;
      SetUiColor(v6 + 0xFF00, color);
      v3 = v6;
    }
    ++v3;
    i += 6;
    v6 = v3;
  }
  while ( i < 396 );
  do
  {
    (&g_CustomUiColors)[v0] = (unsigned __int32 *)GetSysColor(v0 + 1);
    ++v0;
  }
  while ( v0 < 0x10 );
}
//////////////////////////////////////////////////////////////////////////

*/

#include "colorhack.hpp"

#include <dbghelp.h>
#include <engextcpp.hpp>

#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <memory>

#include "strings.hpp"

namespace wa {

WDbgArkColorHack::WDbgArkColorHack() : m_inited(false),
                                       m_g_ui_colors(nullptr),
                                       m_g_out_mask_ui_colors(nullptr),
                                       m_internal_colors(),
                                       tp(nullptr),
                                       m_cur_theme(),
                                       m_themes(),
                                       out(),
                                       warn(),
                                       err(),
                                       bprinter_out() {
    try {
        if ( !IsWinDbgWindow() )
            throw ExtStatusException(S_OK, "Can't find WinDBG window");

        tp.reset(new bprinter::TablePrinter(&bprinter_out));

        tp->AddColumn("DML name", 15);
        tp->AddColumn("Description", 70);
        tp->AddColumn("Original", 10);
        tp->AddColumn("New color", 10);

        InitThemes();

        uintptr_t windbg_module_start = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));

        if ( !windbg_module_start )
            throw ExtStatusException(S_OK, "GetModuleHandle failed");

        PIMAGE_NT_HEADERS nth = ImageNtHeader(reinterpret_cast<PVOID>(windbg_module_start));

        if ( !nth )
            throw ExtStatusException(S_OK, "Can't get NT header");

        uintptr_t windbg_module_end = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(windbg_module_start) +\
            static_cast<ptrdiff_t>(nth->OptionalHeader.SizeOfImage));

        PIMAGE_SECTION_HEADER sech = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<char*>(nth) +\
            sizeof(*nth));

        PIMAGE_SECTION_HEADER sech_text = nullptr;
        PIMAGE_SECTION_HEADER sech_data = nullptr;

        for ( __int16 i = 0; i < nth->FileHeader.NumberOfSections; i++ ) {
            std::string section_name = reinterpret_cast<char*>(&sech->Name[0]);

            if ( sech_text && sech_data )
                break;
            else if ( section_name == ".text" )
                sech_text = sech;
            else if ( section_name == ".data" )
                sech_data = sech;

            sech++;
        }

        if ( !sech_text || !sech_data )
            throw ExtStatusException(S_OK, "Can't get sections header");

        uintptr_t start_data = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(windbg_module_start) +\
            static_cast<ptrdiff_t>(sech_data->VirtualAddress));

        uintptr_t end_data = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(start_data) +\
            static_cast<ptrdiff_t>(sech_data->Misc.VirtualSize));

        uintptr_t start_text = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(windbg_module_start) +\
            static_cast<ptrdiff_t>(sech_text->VirtualAddress));

        uintptr_t end_text = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(start_text) +\
            static_cast<ptrdiff_t>(sech_text->Misc.VirtualSize));

        if ( start_data >= windbg_module_end || end_data > windbg_module_end ||
             start_text >= windbg_module_end || end_text > windbg_module_end ) {
                 throw ExtStatusException(S_OK, "Something is wrong");
        }

        uintptr_t* mem_point = reinterpret_cast<uintptr_t*>(start_data);
        uintptr_t* mem_point_end = reinterpret_cast<uintptr_t*>(end_data);

        while ( mem_point < mem_point_end ) {
            try {
                if ( *mem_point >= start_text && *mem_point <= end_text ) {
                    std::wstring check_sig = reinterpret_cast<wchar_t*>(*mem_point);
                    if ( check_sig == L"Background" )
                        m_g_ui_colors = reinterpret_cast<UiColor*>(mem_point);
                    else if ( check_sig == L"Normal level command window text" )
                        m_g_out_mask_ui_colors = reinterpret_cast<UiColor*>(mem_point);
                    else if ( m_g_ui_colors && m_g_out_mask_ui_colors )
                        break;
                }
            }
            catch( ... ) { }    // continue

            mem_point++;
        }

        if ( !m_g_ui_colors || !m_g_out_mask_ui_colors )
            throw ExtStatusException(S_OK, "WinDbg internal structures are not found");

        UiColor* loc_ui_color = m_g_ui_colors;

        while ( loc_ui_color->description ) {
            m_internal_colors.push_back(ConvertUiColorToInternal(loc_ui_color, UiColorsType));
            loc_ui_color++;
        }

        loc_ui_color = m_g_out_mask_ui_colors;

        while ( loc_ui_color->description ) {
            m_internal_colors.push_back(ConvertUiColorToInternal(loc_ui_color, UiColorsOutMaskType));
            loc_ui_color++;
        }

        m_inited = true;
    }
    catch ( const ExtStatusException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( ... ) {
        err << __FUNCTION__ << ": exception error" << endlerr;
    }
}

BOOL CALLBACK WDbgArkColorHack::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    bool*            found = reinterpret_cast<bool*>(lParam);
    unsigned __int32 pid   = 0;

    GetWindowThreadProcessId(hwnd, reinterpret_cast<LPDWORD>(&pid));

    if ( pid == GetCurrentProcessId() ) {
        HWND top_window = GetTopWindow(hwnd);

        if ( top_window ) {
            size_t window_text_len = static_cast<size_t>(GetWindowTextLength(top_window));

            if ( window_text_len ) {
                std::unique_ptr<char[]> test_name(new char[window_text_len]);

                if ( GetWindowText(top_window, test_name.get(), static_cast<int>(window_text_len)) ) {
                    std::string window_text_name = test_name.get();

                    if ( window_text_name.find("WinDbg:") != std::string::npos ) {
                        *found = true;
                        return FALSE;  // stop enumeration
                    }
                }
            }
        }
    }

    return TRUE;
}

bool WDbgArkColorHack::IsWinDbgWindow(void) {
    bool found = false;

    if ( !EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&found)) && !found )
        return false;

    return true;
}

void WDbgArkColorHack::PrintInformation(void) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return;
    }

    tp->PrintHeader();

    for ( const InternalUiColor &internal_color : m_internal_colors ) {
        std::stringstream original_color;
        original_color << std::internal << std::setw(10) << std::setfill('0');
        original_color << std::hex << std::showbase << internal_color.orig_color;

        std::stringstream new_color;
        new_color << std::internal << std::setw(10) << std::setfill('0');
        new_color << std::hex << std::showbase << internal_color.new_color;

        *tp << internal_color.dml_name << internal_color.description << original_color.str() << new_color.str();
        tp->flush_out();
        tp->PrintFooter();
    }

    tp->PrintFooter();
}

void WDbgArkColorHack::PrintMemoryInfo(void) {
    try {
        out << "--------------------------------------------------------------------------" << endlout;

        UiColor* loc_ui_color = m_g_ui_colors;
        while ( loc_ui_color->description ) {
            out << "Description : " << wstring_to_string(loc_ui_color->description) << endlout;
            out << "DML name    : " << wstring_to_string(loc_ui_color->dml_name) << endlout;
            out << "Colorref    : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->color << endlout;
            out << "Intcolorref : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->int_color << endlout;
            out << "--------------------------------------------------------------------------" << endlout;

            loc_ui_color++;
        }

        loc_ui_color = m_g_out_mask_ui_colors;
        while ( loc_ui_color->description ) {
            out << "Description : " << wstring_to_string(loc_ui_color->description) << endlout;
            out << "DML name    : " << wstring_to_string(loc_ui_color->dml_name) << endlout;
            out << "Colorref    : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->color << endlout;
            out << "Intcolorref : " << std::internal << std::setw(8) << std::setfill('0');
            out << std::hex << std::showbase << loc_ui_color->int_color << endlout;
            out << "--------------------------------------------------------------------------" << endlout;

            loc_ui_color++;
        }
    }
    catch( ... ) {
        err << __FUNCTION__ << ": exception error" << endlerr;
    }
}

void WDbgArkColorHack::InitThemes(void) {
    m_themes["default"];
    // backgrounds
    m_themes["default"].push_back(theme_elem("wbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("normbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("uslbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("errbg", COLOR_HACK_BG_ERROR));     // !!!
    m_themes["default"].push_back(theme_elem("warnbg", COLOR_HACK_BG_WARNING));  // !!!
    m_themes["default"].push_back(theme_elem("verbbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("promptbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("promptregbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("extbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("dbgbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("dbgpbg", COLOR_HACK_BG_DEFAULT));
    m_themes["default"].push_back(theme_elem("symbg", COLOR_HACK_BG_DEFAULT));
    // foregrounds
    m_themes["default"].push_back(theme_elem("wfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("uslfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("normfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("verbfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("promptfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("promptregfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("extfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("dbgfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("dbgpfg", COLOR_HACK_FG_DEFAULT));
    m_themes["default"].push_back(theme_elem("symfg", COLOR_HACK_FG_DEFAULT));
}

bool WDbgArkColorHack::SetTheme(const std::string &theme_name) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return false;
    }

    if ( m_cur_theme == theme_name )
        return true;

    themes::const_iterator it = m_themes.find(theme_name);

    if ( it == m_themes.end() ) {
        err << __FUNCTION__ << ": failed to find theme " << theme_name << endlerr;
        return false;
    }

    theme_elems elems = it->second;

    for ( const theme_elem &element : elems ) {
        if ( !SetColor(element.first, element.second) ) {
            err << __FUNCTION__ << ": failed to set new color for " << element.first << endlerr;
            RevertColors();
            return false;
        }
    }

    m_cur_theme = theme_name;
    return true;
}

WDbgArkColorHack::InternalUiColor WDbgArkColorHack::ConvertUiColorToInternal(UiColor* ui_color,
                                                                             const UiColorType ui_color_type) {
    InternalUiColor internal_color;
    std::memset(&internal_color, 0, sizeof(internal_color));

    internal_color.ui_color = ui_color;
    internal_color.is_changed = false;
    internal_color.ui_color_type = ui_color_type;
    internal_color.description = wstring_to_string(ui_color->description);

    std::string dml_name = wstring_to_string(ui_color->dml_name);
    std::transform(dml_name.begin(), dml_name.end(), dml_name.begin(), tolower);
    internal_color.dml_name = dml_name;

    internal_color.orig_color = ui_color->color;
    internal_color.orig_int_color = ui_color->int_color;

    return internal_color;
}

void WDbgArkColorHack::RevertColors(void) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return;
    }

    try {
        for ( InternalUiColor &internal_color : m_internal_colors ) {
            if ( internal_color.is_changed ) {
                InterlockedExchange(&(internal_color.ui_color->color),
                                    static_cast<LONG>(internal_color.orig_color));

                InterlockedExchange(&(internal_color.ui_color->int_color),
                                    static_cast<LONG>(internal_color.orig_int_color));

                internal_color.new_color = internal_color.new_int_color = RGB(0, 0, 0);
                internal_color.is_changed = false;
            }
        }
    }
    catch( ... ) {
        err << __FUNCTION__ << ": exception error" << endlerr;
    }

    m_cur_theme.clear();
}

bool WDbgArkColorHack::SetColor(const std::string &dml_name, const COLORREF color) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return false;
    }

    vecUiColor::iterator it = std::find_if(m_internal_colors.begin(),
                                           m_internal_colors.end(),
                                           [&dml_name](const InternalUiColor &ui_color) {
                                               return ui_color.dml_name == dml_name; });

    if ( it != m_internal_colors.end() ) {
        // do not touch original color
        it->new_color = color;
        // memory modification
        InterlockedExchange(&it->ui_color->color, static_cast<LONG>(color));
        // memory modification
        InterlockedExchange(&it->ui_color->int_color, static_cast<LONG>(color));
        it->is_changed = true;

        return true;
    }

    return false;
}

}   // namespace wa
