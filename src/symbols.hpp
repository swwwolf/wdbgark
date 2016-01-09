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

#ifndef SYMBOLS_HPP_
#define SYMBOLS_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <utility>

namespace wa {
//////////////////////////////////////////////////////////////////////////
// helpers
//////////////////////////////////////////////////////////////////////////
class WDbgArkSymbolsBase {
 public:
    WDbgArkSymbolsBase();
    virtual ~WDbgArkSymbolsBase() {}

    std::pair<HRESULT, std::string> GetNameByOffset(const uint64_t address);
    HRESULT GetModuleNames(const uint64_t address,
                           std::string* image_name,
                           std::string* module_name,
                           std::string* loaded_image_name);
    bool CheckSymbolsPath(const bool display_error,
                          const std::string& test_path = "http://msdl.microsoft.com/download/symbols");
    HRESULT AppendSymbolPath(const std::string& symbol_path);
    HRESULT AppendImagePath(const std::string& image_path);
    std::string GetSymbolPath(void) const { return m_symbol_path; }
    std::string GetImagePath(void) const { return m_image_path; }

 private:
    bool InitSymbolPath();
    bool InitImagePath();

 private:
    std::string m_symbol_path;
    std::string m_image_path;
    std::stringstream err;
};

}   // namespace wa

#endif  // SYMBOLS_HPP_
