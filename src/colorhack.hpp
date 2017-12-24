/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2018  Vyacheslav Rusakoff
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

#include <bprinter/table_printer.h>

#include <windows.h>

#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include <memory>
#include <unordered_map>

#include "analyze.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
#define COLOR_HACK_BG_DEFAULT   RGB(0xF6, 0xF6, 0xF6)
#define COLOR_HACK_FG_DEFAULT   RGB(0x00, 0x00, 0x00)
#define COLOR_HACK_BG_ERROR     RGB(0xFF, 0xBF, 0xBF)
#define COLOR_HACK_BG_WARNING   RGB(0xFF, 0xFF, 0xBF)
//////////////////////////////////////////////////////////////////////////
// hack WinDbg colors
//////////////////////////////////////////////////////////////////////////
class WDbgArkColorHack : public WDbgArkBPProxy<char> {
 public:
    WDbgArkColorHack();
    ~WDbgArkColorHack() { RevertColors(); }

    bool IsInited(void) const { return m_inited; }
    void PrintInformation(void);
    bool SetTheme(const std::string &theme_name);
    void RevertColors(void);

 private:
    //////////////////////////////////////////////////////////////////////////
    enum class UiColorType {
        UiColorsType,
        UiColorsOutMaskType
    };

    typedef struct UiColorTag {
        wchar_t* description;
        wchar_t* dml_name;
        COLORREF color;
        COLORREF int_color;
        void* reserved1;
        void* reserved2;
    } UiColor;

    typedef struct InternalUiColorTag {
        UiColor* ui_color;
        bool is_changed;
        UiColorType ui_color_type;
        std::string description;
        std::string dml_name;
        COLORREF orig_color;
        COLORREF new_color;
        COLORREF orig_int_color;
        COLORREF new_int_color;
    } InternalUiColor;
    //////////////////////////////////////////////////////////////////////////
    using vecUiColor = std::vector<InternalUiColor>;
    using theme_elem = std::pair<std::string, COLORREF>;
    using theme_elems = std::vector<theme_elem>;
    using themes = std::unordered_map<std::string, theme_elems>;
    //////////////////////////////////////////////////////////////////////////
    void PrintMemoryInfo(void) const;
    void InitThemes(void);
    bool SetColor(const std::string &dml_name, const COLORREF color);
    InternalUiColor ConvertUiColorToInternal(UiColor* ui_color, const UiColorType ui_color_type);
    bool IsWinDbgWindow(void);
    bool GetFileVersion(const std::string& file_path,
                        uint16_t* major,
                        uint16_t* minor,
                        uint16_t* build,
                        uint16_t* revision);

    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
    //////////////////////////////////////////////////////////////////////////
    bool m_inited = false;
    UiColor* m_g_ui_colors = nullptr;
    UiColor* m_g_out_mask_ui_colors = nullptr;
    vecUiColor m_internal_colors{};
    std::string m_cur_theme{};
    themes m_themes{};
};

}   // namespace wa

#endif  // COLORHACK_HPP_
