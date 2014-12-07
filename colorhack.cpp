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
                        break;
                    }
                }
            }
            catch( ... ) { }    // continue

            start_data++;
        }

        if ( g_ui_colors && g_out_mask_ui_colors ) {
            UiColor* loc_ui_color = g_ui_colors;

            while ( loc_ui_color->description ) {
                m_internal_colors.push_back(ConvertUiColorToInternal(loc_ui_color, UiColorsType));
                loc_ui_color++;
            }

            loc_ui_color = g_out_mask_ui_colors;

            while ( loc_ui_color->description ) {
                m_internal_colors.push_back(ConvertUiColorToInternal(loc_ui_color, UiColorsOutMaskType));
                loc_ui_color++;
            }

            tp = std::unique_ptr<bprinter::TablePrinter>(new (std::nothrow) bprinter::TablePrinter(&out));

            if ( tp ) {
                m_inited = true;

                tp->AddColumn("DML name", 15);
                tp->AddColumn("Description", 70);
                tp->AddColumn("Original", 10);
                tp->AddColumn("New color", 10);

                InitThemes();
            }
        }
    }
    catch( ... ) {
        err << __FUNCTION__ << ": exception error" << endlerr;
    }

    return m_inited;
}

void WDbgArkColorHack::PrintInformation(void) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return;
    }

    tp->PrintHeader();

    for ( std::vector<InternalUiColor>::const_iterator it = m_internal_colors.begin();
          it != m_internal_colors.end();
          ++it ) {
              std::stringstream original_color;
              original_color << std::internal << std::setw(10) << std::setfill('0');
              original_color << std::hex << std::showbase << it->orig_color;

              std::stringstream new_color;
              new_color << std::internal << std::setw(10) << std::setfill('0');
              new_color << std::hex << std::showbase << it->new_color;

              *tp << it->dml_name << it->description << original_color.str() << new_color.str();
              tp->flush_out();
              tp->PrintFooter();
    }

    tp->PrintFooter();
}

void WDbgArkColorHack::PrintMemoryInfo(void) {
    try {
        out << "--------------------------------------------------------------------------" << endlout;

        UiColor* loc_ui_color = g_ui_colors;
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

        loc_ui_color = g_out_mask_ui_colors;
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

    for ( theme_elems::const_iterator tit = elems.begin(); tit != elems.end(); ++tit ) {
        if ( !SetColor(tit->first, tit->second) ) {
            err << __FUNCTION__ << ": failed to set new color for " << tit->first << endlerr;
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
    ZeroMemory(&internal_color, sizeof(internal_color));

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

std::pair<bool, std::vector<WDbgArkColorHack::InternalUiColor>::iterator>
WDbgArkColorHack::FindIntUiColor(const std::string &dml_name) {
    InternalUiColor result;
    ZeroMemory(&result, sizeof(result));

    std::string check_name = dml_name;
    std::transform(check_name.begin(), check_name.end(), check_name.begin(), tolower);

    for ( std::vector<InternalUiColor>::iterator it = m_internal_colors.begin();
          it != m_internal_colors.end();
          ++it ) {
              if ( it->dml_name == check_name ) {
                  result = (*it);
                  return std::make_pair(true, it);
              }
    }

    return std::make_pair(false, m_internal_colors.end());
}

void WDbgArkColorHack::RevertColors(void) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return;
    }

    try {
        for ( std::vector<InternalUiColor>::iterator it = m_internal_colors.begin();
              it != m_internal_colors.end();
              ++it ) {
                  if ( it->is_changed ) {
                      InterlockedExchange(&(it->ui_color->color),
                                          static_cast<LONG>(it->orig_color));

                      InterlockedExchange(&(it->ui_color->int_color),
                                          static_cast<LONG>(it->orig_int_color));

                      it->new_color = it->new_int_color = RGB(0, 0, 0);
                      it->is_changed = false;
                  }
        }
    }
    catch( ... ) {
        err << __FUNCTION__ << ": exception error" << endlerr;
    }

    m_cur_theme = "";
}

bool WDbgArkColorHack::SetColor(const std::string &dml_name, const COLORREF color) {
    if ( !IsInited() ) {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return false;
    }

    std::pair<bool, std::vector<InternalUiColor>::iterator> result = FindIntUiColor(dml_name);

    if ( result.first ) {
        // do not touch original color
        result.second->new_color = color;
        // in memory modification
        InterlockedExchange(&result.second->ui_color->color, static_cast<LONG>(color));
        // in memory modification
        InterlockedExchange(&result.second->ui_color->int_color, static_cast<LONG>(color));
        result.second->is_changed = true;

        return true;
    }

    return false;
}
