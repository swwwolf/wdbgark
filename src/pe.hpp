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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef _PE_HPP_
#define _PE_HPP_

#include <windows.h>
#ifdef LoadImage
#undef LoadImage
#endif  // LoadImage

#include <string>
#include <sstream>
#include <memory>
#include <utility>

#include "symbols.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
// PE nt image headers interface
//////////////////////////////////////////////////////////////////////////
class IWDbgArkPeNtHeaders {
 public:
    virtual ~IWDbgArkPeNtHeaders() {}

    virtual bool IsPePlus() const = 0;
    virtual IMAGE_NT_HEADERS* GetPtr() const = 0;
    virtual IMAGE_FILE_HEADER* GetFileHeader() const = 0;
    virtual uint64_t GetImageBase() const = 0;
    virtual uint32_t GetImageSize() const = 0;
    virtual uint32_t GetHeadersSize() const = 0;
    virtual uint16_t GetSubsystem() const = 0;
    virtual uint32_t GetChecksum() const = 0;
    virtual uint32_t GetTimeDateStamp() const = 0;
};

using NtHeaders = std::unique_ptr<IWDbgArkPeNtHeaders>;

//////////////////////////////////////////////////////////////////////////
// PE nt image headers template class
//////////////////////////////////////////////////////////////////////////
template<typename T> class WDbgArkPeNtHeaders : IWDbgArkPeNtHeaders {
 public:
    explicit WDbgArkPeNtHeaders(const IMAGE_NT_HEADERS* image_nt_headers)
        : m_headers(reinterpret_cast<T*>(const_cast<IMAGE_NT_HEADERS*>(image_nt_headers))) {}

    virtual ~WDbgArkPeNtHeaders() {}

    bool IsPePlus() const { return (m_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC); }
    IMAGE_NT_HEADERS* GetPtr() const { return reinterpret_cast<IMAGE_NT_HEADERS*>(m_headers); }
    IMAGE_FILE_HEADER* GetFileHeader() const { return &m_headers->FileHeader; }
    uint64_t GetImageBase() const { return static_cast<uint64_t>(m_headers->OptionalHeader.ImageBase); }
    uint32_t GetImageSize() const { return m_headers->OptionalHeader.SizeOfImage; }
    uint32_t GetHeadersSize() const { return m_headers->OptionalHeader.SizeOfHeaders; }
    uint16_t GetSubsystem() const { return m_headers->OptionalHeader.Subsystem; }
    uint32_t GetChecksum() const { return m_headers->OptionalHeader.CheckSum; }
    uint32_t GetTimeDateStamp() const { return m_headers->FileHeader.TimeDateStamp; }

 private:
    T* m_headers;
};

NtHeaders GetNtHeaders(const IMAGE_NT_HEADERS* nth);

//////////////////////////////////////////////////////////////////////////
// PE format helper class
//////////////////////////////////////////////////////////////////////////
class WDbgArkPe {
 public:
    using unique_buf = std::unique_ptr<uint8_t[]>;

    // read PE image from file, map and apply relocations
    WDbgArkPe(const std::wstring &path,
              const uint64_t base_address,
              const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base);

    // read PE image from file and map without applying relocations
    explicit WDbgArkPe(const std::wstring &path,
                       const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base) : WDbgArkPe(path, 0ULL, symbols_base) {}

    // read PE image from target memory without applying relocations
    WDbgArkPe(const uint64_t base_address,
              const size_t size,
              const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base);

    ~WDbgArkPe();

    bool IsValid() const { return m_valid; }
    bool IsRelocated() const { return m_relocated; }
    void* GetBase() const { return m_load_base; }
    uint64_t GetBaseRelocated() const { return m_relocated_base; }
    uint64_t GetReadMemoryBase() const { return m_read_memory_base; }
    uint32_t GetSizeOfImage();
    bool VerifyChecksum(const unique_buf &buffer);
    bool GetImageFirstSection(IMAGE_SECTION_HEADER** section_header);
    bool GetImageSection(const std::string &name, IMAGE_SECTION_HEADER* section_header);

 private:
    bool MapImage(const uint64_t base_address = 0ULL);
    bool ReadMapMappedImage(const uint64_t base_address, const size_t size);
    bool ReadImage(unique_buf* buffer);
    bool LoadImage(const unique_buf &buffer, const bool mapped = false);
    bool RelocateImage(const uint64_t base_address = 0ULL);
    IMAGE_BASE_RELOCATION* RelocateBlock(const uint64_t address,
                                         const size_t count,
                                         const uint16_t* type_offset,
                                         const int64_t delta);

    bool GetNtHeaders(NtHeaders* nth) { return GetNtHeaders(GetBase(), nth); }
    bool GetNtHeaders(const void* base, NtHeaders* nth);

 private:
    std::wstring m_path{};
    bool m_valid = false;
    bool m_relocated = false;
    size_t m_file_size = 0;
    void* m_load_base = nullptr;
    uint64_t m_relocated_base = 0ULL;
    uint64_t m_read_memory_base = 0ULL;
    std::shared_ptr<WDbgArkSymbolsBase> m_symbols_base{};
    std::stringstream err{};
};

}   // namespace wa

#endif  // _PE_HPP_
