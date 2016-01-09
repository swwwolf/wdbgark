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

#include "symbols.hpp"

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <memory>
#include <utility>
#include <algorithm>

#include "manipulators.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::WDbgArkSymbolsBase() : m_symbol_path(), m_image_path(), err() {
    if ( !InitSymbolPath() )
        err << wa::showminus << __FUNCTION__ ": InitSymbolPath failed" << endlerr;

    if ( !InitImagePath() )
        err << wa::showminus << __FUNCTION__ ": InitImagePath failed" << endlerr;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkSymbolsBase::InitSymbolPath() {
    ULONG sym_buf_size = 0;
    HRESULT result = g_Ext->m_Symbols->GetSymbolPath(nullptr, 0, &sym_buf_size);

    if ( SUCCEEDED(result) ) {
        std::unique_ptr<char[]> sym_path_buf(new char[static_cast<size_t>(sym_buf_size)]);

        result = g_Ext->m_Symbols->GetSymbolPath(sym_path_buf.get(), sym_buf_size, &sym_buf_size);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ ": GetSymbolPath failed" << endlerr;
        } else {
            m_symbol_path.clear();
            m_symbol_path = sym_path_buf.get();
            return true;
        }
    } else {
        err << wa::showminus << __FUNCTION__ ": GetSymbolPath failed" << endlerr;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkSymbolsBase::InitImagePath() {
    ULONG img_buf_size = 0;
    HRESULT result = g_Ext->m_Symbols->GetImagePath(nullptr, 0, &img_buf_size);

    if ( SUCCEEDED(result) ) {
        std::unique_ptr<char[]> img_path_buf(new char[static_cast<size_t>(img_buf_size)]);

        result = g_Ext->m_Symbols->GetSymbolPath(img_path_buf.get(), img_buf_size, &img_buf_size);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ ": GetImagePath failed" << endlerr;
        } else {
            m_image_path.clear();
            m_image_path = img_path_buf.get();
            return true;
        }
    } else {
        err << wa::showminus << __FUNCTION__ ": GetImagePath failed" << endlerr;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::GetModuleNames(const uint64_t address,
                                           std::string* image_name,
                                           std::string* module_name,
                                           std::string* loaded_image_name) {
    ExtCaptureOutputA ignore_output;

    if ( !address )
        return E_INVALIDARG;

    ignore_output.Start();

    uint32_t module_index = 0;
    uint64_t module_base  = 0;
    HRESULT result = g_Ext->m_Symbols->GetModuleByOffset(address,
                                                         0,
                                                         reinterpret_cast<PULONG>(&module_index),
                                                         &module_base);

    if ( SUCCEEDED(result) ) {
        uint32_t img_name_size           = 0;
        uint32_t module_name_size        = 0;
        uint32_t loaded_module_name_size = 0;

        result = g_Ext->m_Symbols->GetModuleNames(module_index,
                                                  module_base,
                                                  NULL,
                                                  0,
                                                  reinterpret_cast<PULONG>(&img_name_size),
                                                  NULL,
                                                  0,
                                                  reinterpret_cast<PULONG>(&module_name_size),
                                                  NULL,
                                                  0,
                                                  reinterpret_cast<PULONG>(&loaded_module_name_size));

        if ( SUCCEEDED(result) ) {
            std::unique_ptr<char[]> buf1;
            size_t img_name_buf_length = static_cast<size_t>(img_name_size + 1);
            buf1.reset(new char[img_name_buf_length]);
            std::memset(buf1.get(), 0, img_name_buf_length);

            std::unique_ptr<char[]> buf2;
            size_t module_name_buf_length = static_cast<size_t>(module_name_size + 1);
            buf2.reset(new char[module_name_buf_length]);
            std::memset(buf2.get(), 0, module_name_buf_length);

            std::unique_ptr<char[]> buf3;
            size_t loaded_module_name_buf_length = static_cast<size_t>(loaded_module_name_size + 1);
            buf3.reset(new char[loaded_module_name_buf_length]);
            std::memset(buf3.get(), 0, loaded_module_name_buf_length);

            result = g_Ext->m_Symbols->GetModuleNames(module_index,
                                                      module_base,
                                                      buf1.get(),
                                                      static_cast<ULONG>(img_name_buf_length),
                                                      nullptr,
                                                      buf2.get(),
                                                      static_cast<ULONG>(module_name_buf_length),
                                                      nullptr,
                                                      buf3.get(),
                                                      static_cast<ULONG>(loaded_module_name_buf_length),
                                                      nullptr);

            if ( SUCCEEDED(result) ) {
                image_name->assign(buf1.get());
                std::transform(image_name->begin(), image_name->end(), image_name->begin(), tolower);

                module_name->assign(buf2.get());
                std::transform(module_name->begin(), module_name->end(), module_name->begin(), tolower);

                loaded_image_name->assign(buf3.get());
                std::transform(loaded_image_name->begin(),
                               loaded_image_name->end(),
                               loaded_image_name->begin(),
                               tolower);
            }
        }
    }

    ignore_output.Stop();
    return result;
}
//////////////////////////////////////////////////////////////////////////
std::pair<HRESULT, std::string> WDbgArkSymbolsBase::GetNameByOffset(const uint64_t address) {
    std::string output_name = "*UNKNOWN*";

    if ( !address )
        return std::make_pair(E_INVALIDARG, output_name);

    ExtCaptureOutputA ignore_output;
    ignore_output.Start();

    uint32_t name_buffer_size = 0;
    uint64_t displacement     = 0;
    HRESULT result = g_Ext->m_Symbols->GetNameByOffset(address,
                                                       NULL,
                                                       0,
                                                       reinterpret_cast<PULONG>(&name_buffer_size),
                                                       &displacement);
    ignore_output.Stop();

    if ( SUCCEEDED(result) && name_buffer_size ) {
        size_t buf_size = static_cast<size_t>(name_buffer_size + 1);
        std::unique_ptr<char[]> tmp_name(new char[buf_size]);
        std::memset(tmp_name.get(), 0, buf_size);

        ignore_output.Start();
        result = g_Ext->m_Symbols->GetNameByOffset(address, tmp_name.get(), name_buffer_size, nullptr, nullptr);
        ignore_output.Stop();

        if ( SUCCEEDED(result) ) {
            std::stringstream stream_name;

            stream_name << tmp_name.get();

            if ( displacement )
                stream_name << "+" << std::hex << std::showbase << displacement;

            output_name = normalize_special_chars(stream_name.str());
        }
    }

    return std::make_pair(result, output_name);
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkSymbolsBase::CheckSymbolsPath(const bool display_error, const std::string& test_path) {
    std::string check_path = GetSymbolPath();

    if ( check_path.empty() || check_path == " " ) {
        if ( display_error ) {
            err << wa::showminus << __FUNCTION__ << ": seems that your symbol path is empty. Fix it!" << endlerr;
        }
    } else if ( check_path.find(test_path) == std::string::npos ) {
        if ( display_error ) {
            std::stringstream warn;

            warn << wa::showqmark << __FUNCTION__ << ": seems that your symbol path may be incorrect. ";
            warn << "Include symbol path (" << test_path << ")" << endlwarn;
        }
    } else {
        return true;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::AppendSymbolPath(const std::string& symbol_path) {
    HRESULT result = g_Ext->m_Symbols->AppendSymbolPath(symbol_path.c_str());

    if ( !InitSymbolPath() )
        err << wa::showminus << __FUNCTION__ ": InitSymbolPath failed" << endlerr;

    return result;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::AppendImagePath(const std::string& image_path) {
    HRESULT result = g_Ext->m_Symbols->AppendImagePath(image_path.c_str());

    if ( !InitImagePath() )
        err << wa::showminus << __FUNCTION__ ": InitImagePath failed" << endlerr;

    return result;
}
//////////////////////////////////////////////////////////////////////////
}   // namespace wa
