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

#include "symbols.hpp"

#include <engextcpp.hpp>
#include <dbghelp.h>

#include <string>
#include <sstream>
#include <memory>
#include <utility>
#include <algorithm>

#include "manipulators.hpp"
#include "winapi.hpp"
#include "pe.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::WDbgArkSymbolsBase() {
    if ( !InitSymbolPath() ) {
        err << wa::showminus << __FUNCTION__ ": InitSymbolPath failed" << endlerr;
    }

    if ( !InitImagePath() ) {
        err << wa::showminus << __FUNCTION__ ": InitImagePath failed" << endlerr;
    }
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkSymbolsBase::InitSymbolPath() {
    ULONG sym_buf_size = 0;
    HRESULT result = g_Ext->m_Symbols->GetSymbolPath(nullptr, 0, &sym_buf_size);

    if ( SUCCEEDED(result) ) {
        auto sym_path_buf = std::make_unique<char[]>(static_cast<size_t>(sym_buf_size));

        result = g_Ext->m_Symbols->GetSymbolPath(sym_path_buf.get(), sym_buf_size, &sym_buf_size);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ ": GetSymbolPath failed" << endlerr;
        } else {
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
        std::unique_ptr<char[]> img_path_buf = std::make_unique<char[]>(static_cast<size_t>(img_buf_size));

        result = g_Ext->m_Symbols->GetImagePath(img_path_buf.get(), img_buf_size, &img_buf_size);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ ": GetImagePath failed" << endlerr;
        } else {
            m_image_path = img_path_buf.get();
            return true;
        }
    } else {
        err << wa::showminus << __FUNCTION__ ": GetImagePath failed" << endlerr;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::FindExecutableImage(const std::string &search_path,
                                                                         const std::string &image_name,
                                                                         const DEBUG_MODULE_PARAMETERS &parameters) {
    if ( search_path.empty() || image_name.empty() ) {
        return std::make_pair(E_INVALIDARG, m_unknown_name);
    }

    char image_file_path[MAX_PATH + 1] = { 0 };
    HANDLE exe_file = FindExecutableImageEx(image_name.c_str(),
                                            search_path.c_str(),
                                            reinterpret_cast<PSTR>(&image_file_path),
                                            FindExecutableImageProc,
                                            reinterpret_cast<void*>(const_cast<DEBUG_MODULE_PARAMETERS*>(&parameters)));

    if ( exe_file ) {
        CloseHandle(exe_file);
        return std::make_pair(S_OK, std::string(image_file_path));
    }

    return std::make_pair(E_NOT_SET, m_unknown_name);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::FindExecutableImageInternal(
    const std::string &image_name,
    const DEBUG_MODULE_PARAMETERS &parameters) {
    ResultString result_string = FindExecutableImage(GetImagePath(), image_name, parameters);

    if ( SUCCEEDED(result_string.first) ) {
        return std::make_pair(result_string.first, result_string.second);
    }

    result_string = SymFindExecutableImage(GetSymbolPath(), image_name, parameters);

    if ( SUCCEEDED(result_string.first) ) {
        return std::make_pair(result_string.first, result_string.second);
    }

    result_string = SymFindExecutableImage(GetImagePath(), image_name, parameters);

    if ( SUCCEEDED(result_string.first) ) {
        return std::make_pair(result_string.first, result_string.second);
    }

    return std::make_pair(E_NOT_SET, m_unknown_name);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::SymFindExecutableImage(const std::string &search_path,
                                                                            const std::string &image_name,
                                                                            const DEBUG_MODULE_PARAMETERS &parameters) {
    if ( search_path.empty() || image_name.empty() ) {
        return std::make_pair(E_INVALIDARG, m_unknown_name);
    }

    char image_file_path[MAX_PATH + 1] = { 0 };
    const auto result = SymFindFileInPath(GetCurrentProcess(),
                                          search_path.c_str(),
                                          image_name.c_str(),
                                          reinterpret_cast<PVOID>(const_cast<ULONG*>(&parameters.TimeDateStamp)),
                                          parameters.Size,
                                          0,
                                          SSRVOPT_DWORDPTR,
                                          reinterpret_cast<PSTR>(&image_file_path),
                                          SymFindFileInPathProc,
                                          reinterpret_cast<void*>(const_cast<DEBUG_MODULE_PARAMETERS*>(&parameters)));

    if ( result ) {
        return std::make_pair(S_OK, std::string(image_file_path));
    }

    auto alias_result = FindImageNameByAlias(image_name);

    if ( SUCCEEDED(alias_result.first) ) {
        return SymFindExecutableImage(search_path, alias_result.second, parameters);
    }

    return std::make_pair(E_NOT_SET, m_unknown_name);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::FindImageNameByAlias(const std::string &image_name) {
    for ( const auto &aliases : m_aliases ) {
        const auto it = std::find_if(std::begin(aliases.second),
                                     std::end(aliases.second),
                                     [&image_name](const std::string &alias) { return alias == image_name; });

        if ( it != std::end(aliases.second) ) {
            return std::make_pair(S_OK, aliases.first);
        }
    }

    return std::make_pair(E_NOT_SET, m_unknown_name);
}
//////////////////////////////////////////////////////////////////////////
BOOL WDbgArkSymbolsBase::FindExecutableImageProc(HANDLE file_handle, const char* file_name, void* data) {
    UNREFERENCED_PARAMETER(file_handle);
    return !SymFindFileInPathProc(file_name, data);     // invert SymFindFileInPathProc result
}
//////////////////////////////////////////////////////////////////////////
BOOL WDbgArkSymbolsBase::SymFindFileInPathProc(const char* file_name, void* data) {
    HANDLE hfile = INVALID_HANDLE_VALUE;
    HANDLE hmap = nullptr;
    void* base = nullptr;

    BOOL result = TRUE;     // continue searching

    if ( !MapImage(file_name, &hfile, &hmap, &base) ) {
        return result;
    }

    auto header = ::ImageNtHeader(base);

    if ( header ) {
        auto nth = wa::GetNtHeaders(header);

        PDEBUG_MODULE_PARAMETERS parameters = reinterpret_cast<PDEBUG_MODULE_PARAMETERS>(data);

        if ( parameters->Size == nth->GetImageSize() &&
             parameters->TimeDateStamp == nth->GetTimeDateStamp() &&
             parameters->Checksum == nth->GetChecksum() ) {
            result = FALSE;     // end the search
        }
    }

    UnmapImage(&hfile, &hmap, &base);
    return result;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::GetModuleNames(const uint64_t address,
                                           std::string* image_name,
                                           std::string* module_name,
                                           std::string* loaded_image_name) {
    if ( !address ) {
        return E_INVALIDARG;
    }

    ExtCaptureOutputA ignore_output;
    ignore_output.Start();

    uint32_t index = 0;
    uint64_t base  = 0;
    HRESULT result = g_Ext->m_Symbols->GetModuleByOffset(address, 0, reinterpret_cast<PULONG>(&index), &base);

    if ( SUCCEEDED(result) ) {
        uint32_t img_name_size = 0;
        uint32_t module_name_size = 0;
        uint32_t loaded_module_name_size = 0;

        result = g_Ext->m_Symbols->GetModuleNames(index,
                                                  base,
                                                  nullptr,
                                                  0,
                                                  reinterpret_cast<PULONG>(&img_name_size),
                                                  nullptr,
                                                  0,
                                                  reinterpret_cast<PULONG>(&module_name_size),
                                                  nullptr,
                                                  0,
                                                  reinterpret_cast<PULONG>(&loaded_module_name_size));

        if ( SUCCEEDED(result) ) {
            size_t img_name_buf_length = static_cast<size_t>(img_name_size + 1);
            auto buf1 = std::make_unique<char[]>(img_name_buf_length);
            std::memset(buf1.get(), 0, img_name_buf_length);

            size_t module_name_buf_length = static_cast<size_t>(module_name_size + 1);
            auto buf2 = std::make_unique<char[]>(module_name_buf_length);
            std::memset(buf2.get(), 0, module_name_buf_length);

            size_t loaded_module_name_buf_length = static_cast<size_t>(loaded_module_name_size + 1);
            auto buf3 = std::make_unique<char[]>(loaded_module_name_buf_length);
            std::memset(buf3.get(), 0, loaded_module_name_buf_length);

            result = g_Ext->m_Symbols->GetModuleNames(index,
                                                      base,
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
                std::transform(image_name->begin(),
                               image_name->end(),
                               image_name->begin(),
                               [](char c) {return static_cast<char>(tolower(c)); });

                module_name->assign(buf2.get());
                std::transform(module_name->begin(),
                               module_name->end(),
                               module_name->begin(),
                               [](char c) {return static_cast<char>(tolower(c)); });

                loaded_image_name->assign(buf3.get());
                std::transform(loaded_image_name->begin(),
                               loaded_image_name->end(),
                               loaded_image_name->begin(),
                               [](char c) {return static_cast<char>(tolower(c)); });
            }
        }
    }

    return result;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::GetModuleStartSize(const uint64_t address, uint64_t* start, uint32_t* size) const {
    if ( !address ) {
        return E_INVALIDARG;
    }

    ExtCaptureOutputA ignore_output;
    ignore_output.Start();

    uint32_t index = 0;
    uint64_t base = 0;
    HRESULT result = g_Ext->m_Symbols->GetModuleByOffset(address, 0, reinterpret_cast<PULONG>(&index), &base);

    if ( FAILED(result) ) {
        return result;
    }

    DEBUG_MODULE_PARAMETERS parameters;
    result = g_Ext->m_Symbols->GetModuleParameters(1, &base, 0, &parameters);

    if ( FAILED(result) ) {
        return result;
    }

    if ( parameters.Base == DEBUG_INVALID_OFFSET ) {
        return E_POINTER;
    }

    *start = base;
    *size = parameters.Size;

    return S_OK;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::GetFunctionInformation(const std::string &function_name,
                                                   uint64_t* start_offset,
                                                   uint64_t* end_offset) {
    uint64_t offset = 0ULL;

    if ( !g_Ext->GetSymbolOffset(function_name.c_str(), true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": Unable to find " << function_name << endlerr;
        return E_UNEXPECTED;
    }

    return GetFunctionInformation(offset, start_offset, end_offset);
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::GetFunctionInformation(const uint64_t offset,
                                                   uint64_t* start_offset,
                                                   uint64_t* end_offset) {
    *start_offset = 0ULL;
    *end_offset = 0ULL;

    size_t size = 0;

    if ( g_Ext->IsCurMachine64() ) {
        size = sizeof(IMAGE_FUNCTION_ENTRY);
    } else {
        size = sizeof(FPO_DATA);
    }

    std::unique_ptr<uint8_t[]> function_entry = std::make_unique<uint8_t[]>(size);
    auto result = g_Ext->m_Symbols3->GetFunctionEntryByOffset(offset,
                                                              0,
                                                              function_entry.get(),
                                                              static_cast<ULONG>(size),
                                                              nullptr);

    if ( FAILED(result) ) {
        return result;
    }

    if ( g_Ext->IsCurMachine64() ) {
        PIMAGE_FUNCTION_ENTRY entry = reinterpret_cast<PIMAGE_FUNCTION_ENTRY>(function_entry.get());
        *start_offset = entry->StartingAddress;
        *end_offset = entry->EndingAddress;
    } else {
        PFPO_DATA entry = reinterpret_cast<PFPO_DATA>(function_entry.get());
        *start_offset = entry->ulOffStart;
        *end_offset = entry->ulOffStart + entry->cbProcSize;
    }

    return S_OK;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkSymbolsBase::CheckMsSymbolsPath() {
    bool result = false;

    for ( const auto& path : m_ms_symbol_servers ) {
        if ( CheckSymbolsPath(false, path) ) {
            result = true;
        }
    }

    return result;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkSymbolsBase::CheckSymbolsPath(const bool display_error, const std::string &test_path) {
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
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::GetNameByOffset(const uint64_t address) {
    std::string output_name = m_unknown_name;

    if ( !address ) {
        return std::make_pair(E_INVALIDARG, output_name);
    }

    ExtCaptureOutputA ignore_output;
    ignore_output.Start();

    uint32_t name_buffer_size = 0;
    uint64_t displacement = 0;
    HRESULT result = g_Ext->m_Symbols->GetNameByOffset(address,
                                                       nullptr,
                                                       0,
                                                       reinterpret_cast<PULONG>(&name_buffer_size),
                                                       &displacement);
    ignore_output.Stop();

    if ( SUCCEEDED(result) && name_buffer_size ) {
        size_t buf_size = static_cast<size_t>(name_buffer_size + 1);
        auto tmp_name = std::make_unique<char[]>(buf_size);
        std::memset(tmp_name.get(), 0, buf_size);

        ignore_output.Start();
        result = g_Ext->m_Symbols->GetNameByOffset(address, tmp_name.get(), name_buffer_size, nullptr, nullptr);
        ignore_output.Stop();

        if ( SUCCEEDED(result) ) {
            std::stringstream stream_name;

            stream_name << tmp_name.get();

            if ( displacement ) {
                stream_name << "+" << std::hex << std::showbase << displacement;
            }

            output_name = normalize_special_chars(stream_name.str());
        }
    }

    return std::make_pair(result, output_name);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::GetModuleImagePath(const uint64_t address,
                                                                        const bool skip_unloaded) {
    if ( !address ) {
        return std::make_pair(E_INVALIDARG, m_unknown_name);
    }

    ExtCaptureOutputA ignore_output;
    ignore_output.Start();

    uint32_t index = 0;
    uint64_t base = 0;
    HRESULT result = g_Ext->m_Symbols->GetModuleByOffset(address, 0, reinterpret_cast<PULONG>(&index), &base);

    if ( FAILED(result) ) {
        return std::make_pair(result, m_unknown_name);
    }

    if ( skip_unloaded ) {
        DEBUG_MODULE_PARAMETERS parameters;
        result = g_Ext->m_Symbols->GetModuleParameters(1, &base, 0, &parameters);

        if ( FAILED(result) ) {
            return std::make_pair(result, m_unknown_name);
        }

        if ( parameters.Base == DEBUG_INVALID_OFFSET ) {
            return std::make_pair(E_POINTER, m_unknown_name);
        }

        if ( parameters.Flags & DEBUG_MODULE_UNLOADED ) {
            return std::make_pair(E_NOT_SET, m_unknown_name);
        }
    }

    ResultString result_string = GetModuleNameString(DEBUG_MODNAME_MAPPED_IMAGE, index, base);

    if ( SUCCEEDED(result_string.first) ) {
        return std::make_pair(result_string.first, result_string.second);
    }

    return FindModuleImage(base, index);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::GetModuleImagePath(const std::string &module_name,
                                                                        const bool skip_unloaded) {
    ExtCaptureOutputA ignore_output;
    ignore_output.Start();

    uint64_t base = 0;
    HRESULT result = g_Ext->m_Symbols->GetModuleByModuleName(module_name.c_str(), 0, nullptr, &base);

    if ( FAILED(result) ) {
        return std::make_pair(result, m_unknown_name);
    }

    return GetModuleImagePath(base, skip_unloaded);
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::GetModuleNameString(const uint32_t type,
                                                                         const uint32_t index,
                                                                         const uint64_t base) {
    uint32_t len = 0;
    HRESULT result = g_Ext->m_Symbols2->GetModuleNameString(type,
                                                            index,
                                                            base,
                                                            nullptr,
                                                            0,
                                                            reinterpret_cast<PULONG>(&len));

    if ( FAILED(result) ) {
        return std::make_pair(result, m_unknown_name);
    }

    if ( len < 3 ) {
        return std::make_pair(E_NOT_SET, m_unknown_name);
    }

    len++;
    auto tmp_name = std::make_unique<char[]>(static_cast<size_t>(len));
    std::memset(tmp_name.get(), 0, static_cast<size_t>(len));

    result = g_Ext->m_Symbols2->GetModuleNameString(type,
                                                    index,
                                                    base,
                                                    tmp_name.get(),
                                                    len,
                                                    reinterpret_cast<PULONG>(&len));

    return std::make_pair(result, tmp_name.get());
}
//////////////////////////////////////////////////////////////////////////
WDbgArkSymbolsBase::ResultString WDbgArkSymbolsBase::FindModuleImage(const uint64_t base, const uint32_t index) {
    DEBUG_MODULE_PARAMETERS parameters;
    HRESULT result = g_Ext->m_Symbols->GetModuleParameters(1, const_cast<uint64_t*>(&base), index, &parameters);

    if ( FAILED(result) ) {
        return std::make_pair(result, m_unknown_name);
    }

    if ( parameters.Base == DEBUG_INVALID_OFFSET ) {
        return std::make_pair(E_POINTER, m_unknown_name);
    }

    std::string image_name;
    std::string module_name;
    std::string loaded_image_name;

    result = GetModuleNames(base, &image_name, &module_name, &loaded_image_name);

    if ( FAILED(result) ) {
        return std::make_pair(result, m_unknown_name);
    }

    size_t pos = image_name.find_last_of("/\\");

    if ( pos != std::string::npos ) {
        image_name = image_name.substr(pos + 1);
    }

    return FindExecutableImageInternal(image_name, parameters);
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::AppendSymbolPath(const std::string &symbol_path) {
    HRESULT result = g_Ext->m_Symbols->AppendSymbolPath(symbol_path.c_str());

    if ( !InitSymbolPath() ) {
        err << wa::showminus << __FUNCTION__ ": InitSymbolPath failed" << endlerr;
    }

    return result;
}
//////////////////////////////////////////////////////////////////////////
HRESULT WDbgArkSymbolsBase::AppendImagePath(const std::string &image_path) {
    HRESULT result = g_Ext->m_Symbols->AppendImagePath(image_path.c_str());

    if ( !InitImagePath() ) {
        err << wa::showminus << __FUNCTION__ ": InitImagePath failed" << endlerr;
    }

    return result;
}
//////////////////////////////////////////////////////////////////////////
}   // namespace wa
