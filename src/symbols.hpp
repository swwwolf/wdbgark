/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2016  Vyacheslav Rusakoff
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

#ifndef SYMBOLS_HPP_
#define SYMBOLS_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <utility>
#include <map>
#include <vector>
#include <array>

namespace wa {

class WDbgArkSymbolsBase {
 public:
    using ResultString = std::pair<HRESULT, std::string>;

    WDbgArkSymbolsBase();
    virtual ~WDbgArkSymbolsBase() {}

    std::string GetSymbolPath(void) const { return m_symbol_path; }
    std::string GetImagePath(void) const { return m_image_path; }

    ResultString GetNameByOffset(const uint64_t address);
    ResultString GetModuleImagePath(const uint64_t address, const bool skip_unloaded);
    ResultString GetModuleImagePath(const std::string &module_name, const bool skip_unloaded);
    ResultString GetModuleNameString(const uint32_t type, const uint32_t index, const uint64_t base);
    ResultString FindModuleImage(const uint64_t base, const uint32_t index);
    HRESULT GetModuleNames(const uint64_t address,
                           std::string* image_name,
                           std::string* module_name,
                           std::string* loaded_image_name);
    HRESULT GetModuleStartSize(const uint64_t address, uint64_t* start, uint32_t* size);
    bool CheckMsSymbolsPath();
    bool CheckSymbolsPath(const bool display_error,
                          const std::string &test_path = "https://msdl.microsoft.com/download/symbols");
    HRESULT AppendSymbolPath(const std::string &symbol_path);
    HRESULT AppendImagePath(const std::string &image_path);

 private:
    using ImageNames = std::vector<std::string>;
    using ModuleAliases = std::map<std::string, ImageNames>;

    bool InitSymbolPath();
    bool InitImagePath();
    ResultString FindExecutableImage(const std::string &search_path,
                                     const std::string &image_name,
                                     const DEBUG_MODULE_PARAMETERS &parameters);
    ResultString FindExecutableImageInternal(const std::string &image_name, const DEBUG_MODULE_PARAMETERS &parameters);
    ResultString SymFindExecutableImage(const std::string &search_path,
                                        const std::string &image_name,
                                        const DEBUG_MODULE_PARAMETERS &parameters);
    ResultString FindImageNameByAlias(const std::string &image_name);
    static BOOL CALLBACK FindExecutableImageProc(HANDLE file_handle, const char* file_name, void* data);
    static BOOL CALLBACK SymFindFileInPathProc(const char* file_name, void* data);

 private:
    const std::string m_unknown_name = "*UNKNOWN*";
    const ModuleAliases m_aliases = {
        { "ntoskrnl.exe", { "ntkrnlup.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe", "xboxkrnlc.exe" } }
    };
    const std::array<std::string, 2> m_ms_symbol_servers = {
        "http://msdl.microsoft.com/download/symbols",
        "https://msdl.microsoft.com/download/symbols"
    };
    std::string m_symbol_path{};
    std::string m_image_path{};
    std::stringstream err{};
};

}   // namespace wa

#endif  // SYMBOLS_HPP_
