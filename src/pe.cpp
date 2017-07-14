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

#include "pe.hpp"

#include <dbghelp.h>

#include <fstream>
#include <string>
#include <sstream>
#include <algorithm>

#include "./ddk.h"

#include "manipulators.hpp"
#include "winapi.hpp"

namespace wa {
NtHeaders GetNtHeaders(const IMAGE_NT_HEADERS* nth) {
    if ( nth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
        return NtHeaders(reinterpret_cast<IWDbgArkPeNtHeaders*>(new WDbgArkPeNtHeaders<IMAGE_NT_HEADERS64>(nth)));
    } else {
        return NtHeaders(reinterpret_cast<IWDbgArkPeNtHeaders*>(new WDbgArkPeNtHeaders<IMAGE_NT_HEADERS32>(nth)));
    }
}

WDbgArkPe::WDbgArkPe(const std::wstring &path,
                     const uint64_t base_address,
                     const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base) : m_path(path),
                                                                                m_symbols_base(symbols_base) {
    m_valid = MapImage(base_address);
}

WDbgArkPe::WDbgArkPe(const uint64_t base_address,
                     const uint32_t size,
                     const std::shared_ptr<WDbgArkSymbolsBase> &symbols_base) : m_symbols_base(symbols_base) {
    m_valid = ReadMapMappedImage(base_address, size);
}

WDbgArkPe::~WDbgArkPe() {
    if ( m_load_base ) {
        VirtualFree(m_load_base, 0, MEM_RELEASE);
    }
}

uint32_t WDbgArkPe::GetSizeOfImage() {
    NtHeaders nth;

    if ( GetNtHeaders(&nth) ) {
        return nth->GetImageSize();
    }

    return 0;
}

bool WDbgArkPe::MapImage(const uint64_t base_address) {
    unique_buf buffer;

    if ( !ReadImage(&buffer) ) {
        err << wa::showminus << __FUNCTION__ ": ReadImage failed" << endlerr;
        return false;
    }

    if ( !VerifyChecksum(buffer) ) {
        err << wa::showminus << __FUNCTION__ ": VerifyChecksum failed" << endlerr;
        return false;
    }

    if ( !LoadImage(buffer) ) {
        err << wa::showminus << __FUNCTION__ ": LoadImage failed" << endlerr;
        return false;
    }

    m_relocated = RelocateImage(base_address);

    if ( m_relocated )
        m_relocated_base = base_address;

    return true;
}

bool WDbgArkPe::ReadMapMappedImage(const uint64_t base_address, const uint32_t size) {
    unique_buf buffer = std::make_unique<uint8_t[]>(size);

    uint32_t read_size = 0UL;
    auto result = g_Ext->m_Data->ReadVirtualUncached(base_address,
                                                     buffer.get(),
                                                     size,
                                                     reinterpret_cast<PULONG>(&read_size));

    // it's OK to read smaller number of bytes due to discardable sections
    if ( FAILED(result) ) {
        err << wa::showminus << __FUNCTION__ ": ReadVirtual failed" << endlerr;
        return false;
    }

    if ( !LoadImage(buffer, true) ) {
        err << wa::showminus << __FUNCTION__ ": LoadImage failed" << endlerr;
        return false;
    }

    m_read_memory_base = base_address;

    return true;
}

bool WDbgArkPe::ReadImage(unique_buf* buffer) {
    std::ifstream file;

    file.open(m_path, std::ifstream::in | std::ifstream::binary);

    if ( file.fail() ) {
        err << wa::showminus << __FUNCTION__ ": file not found" << endlerr;
        return false;
    }

    file.seekg(0, file.end);
    m_file_size = static_cast<size_t>(file.tellg());
    file.seekg(0, file.beg);

    unique_buf temp_buffer = std::make_unique<uint8_t[]>(m_file_size);
    file.read(reinterpret_cast<char*>(temp_buffer.get()), m_file_size);
    auto result = !file.fail();
    file.close();

    if ( result ) {
        buffer->reset(temp_buffer.release());
    }

    return result;
}

bool WDbgArkPe::VerifyChecksum(const unique_buf &buffer) {
    NtHeaders nth;

    if ( !GetNtHeaders(buffer.get(), &nth) ) {
        return false;
    }

    uint32_t header_sum = nth->GetChecksum();

    if ( !header_sum ) {
        return true;
    }

    uint16_t* address = reinterpret_cast<uint16_t*>(buffer.get());
    uint32_t sum = 0;

    for ( uint32_t i = 0; i < m_file_size / sizeof(uint16_t); i++ ) {
        sum += static_cast<uint32_t>(*address);

        if ( HIWORD(sum) != 0 ) {
            sum = LOWORD(sum) + HIWORD(sum);
        }

        address++;
    }

    if ( m_file_size & 1 ) {
        sum += static_cast<uint32_t>(*reinterpret_cast<uint8_t*>(address));

        if ( HIWORD(sum) != 0 ) {
            sum = LOWORD(sum) + HIWORD(sum);
        }
    }

    uint32_t calc_sum = static_cast<uint16_t>(LOWORD(sum) + HIWORD(sum));

    if ( LOWORD(calc_sum) >= LOWORD(header_sum) ) {
        calc_sum -= LOWORD(header_sum);
    } else {
        calc_sum = ((LOWORD(calc_sum) - LOWORD(header_sum)) & 0xFFFF) - 1;
    }

    if ( LOWORD(calc_sum) >= HIWORD(header_sum) ) {
        calc_sum -= HIWORD(header_sum);
    } else {
        calc_sum = ((LOWORD(calc_sum) - HIWORD(header_sum)) & 0xFFFF) - 1;
    }

    calc_sum += static_cast<uint32_t>(m_file_size);

    return (calc_sum == header_sum);
}

bool WDbgArkPe::GetImageFirstSection(IMAGE_SECTION_HEADER** section_header) {
    *section_header = nullptr;

    NtHeaders nth;

    if ( !GetNtHeaders(&nth) ) {
        return false;
    }

    *section_header = IMAGE_FIRST_SECTION(nth->GetPtr());
    return true;
}

bool WDbgArkPe::GetImageSection(const std::string &name, IMAGE_SECTION_HEADER* section_header) {
    NtHeaders nth;

    if ( !GetNtHeaders(&nth) ) {
        return false;
    }

    auto search_name(name);
    std::transform(search_name.begin(), search_name.end(), search_name.begin(), tolower);

    IMAGE_SECTION_HEADER* temp_header = nullptr;

    if ( !GetImageFirstSection(&temp_header) ) {
        return false;
    }

    for ( uint16_t i = 0; i < nth->GetFileHeader()->NumberOfSections; i++ ) {
        char temp_name[9];
        std::memset(temp_name, 0, sizeof(temp_name));
        std::memcpy(temp_name, temp_header[i].Name, sizeof(temp_header[i].Name));

        std::string section_name(temp_name);
        std::transform(section_name.begin(), section_name.end(), section_name.begin(), tolower);

        if ( section_name == search_name ) {
            *section_header = temp_header[i];
            return true;
        }
    }

    return false;
}

bool WDbgArkPe::LoadImage(const unique_buf &buffer, const bool mapped) {
    NtHeaders nth;

    if ( !GetNtHeaders(buffer.get(), &nth) ) {
        return false;
    }

    uint32_t image_size = nth->GetImageSize();

    if ( !image_size || image_size < m_file_size ) {
        return false;
    }

    m_load_base = VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if ( !m_load_base ) {
        std::string lasterr = LastErrorToString(GetLastError());
        err << wa::showminus << __FUNCTION__ ": VirtualAlloc failed : " << lasterr << endlerr;
        return false;
    }

    if ( !mapped ) {
        uint32_t headers_size = nth->GetHeadersSize();
        std::memcpy(m_load_base, buffer.get(), headers_size);

        auto section_header = IMAGE_FIRST_SECTION(nth->GetPtr());

        for ( uint16_t i = 0; i < nth->GetFileHeader()->NumberOfSections; i++ ) {
            if ( !section_header[i].SizeOfRawData ) {
                continue;
            }

            void* section_dst = reinterpret_cast<void*>RtlOffsetToPointer(m_load_base,
                                                                          section_header[i].VirtualAddress);
            void* section_src = reinterpret_cast<void*>RtlOffsetToPointer(buffer.get(),
                                                                          section_header[i].PointerToRawData);
            uint32_t section_size = min(section_header[i].SizeOfRawData, section_header[i].Misc.VirtualSize);

            std::memcpy(section_dst, section_src, section_size);
        }
    } else {
        std::memcpy(m_load_base, buffer.get(), image_size);
    }

    return true;
}

bool WDbgArkPe::RelocateImage(const uint64_t base_address) {
    if ( !base_address ) {
        return false;
    }

    NtHeaders nth;

    if ( !GetNtHeaders(&nth) ) {
        return false;
    }

    if ( nth->GetFileHeader()->Characteristics & IMAGE_FILE_RELOCS_STRIPPED ) {     // it's ok
        return true;
    }

    uint32_t dir_size = 0;
    auto next_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(::ImageDirectoryEntryToDataEx(
        m_load_base,
        true,
        IMAGE_DIRECTORY_ENTRY_BASERELOC,
        reinterpret_cast<PULONG>(&dir_size),
        nullptr));

    if ( !next_relocation || !dir_size ) {
        std::string lasterr = LastErrorToString(GetLastError());
        err << wa::showminus << __FUNCTION__ ": ImageDirectoryEntryToDataEx failed : " << lasterr << endlerr;
        return false;
    }

    int64_t delta = RtlPointerToOffset(nth->GetImageBase(), base_address);
    auto last_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>RtlOffsetToPointer(next_relocation, dir_size);

    while ( next_relocation < last_relocation && next_relocation->SizeOfBlock > 0 ) {
        uint64_t address = reinterpret_cast<uint64_t>RtlOffsetToPointer(m_load_base, next_relocation->VirtualAddress);
        uint32_t count = (next_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        uint16_t* type_offset = reinterpret_cast<uint16_t*>(next_relocation + 1);

        next_relocation = RelocateBlock(address, count, type_offset, delta);

        if ( !next_relocation ) {
            err << wa::showminus << __FUNCTION__ ": RelocateBlock failed" << endlerr;
            return false;
        }
    }

    return true;
}

IMAGE_BASE_RELOCATION* WDbgArkPe::RelocateBlock(const uint64_t address,
                                                const uint32_t count,
                                                const uint16_t* type_offset,
                                                const int64_t delta) {
    auto loc_type_offset = const_cast<uint16_t*>(type_offset);

    for ( uint32_t i = 0; i < count; i++ ) {
        int16_t offset = (*loc_type_offset) & 0xFFF;
        uint16_t type = (*loc_type_offset) >> 12;
        uint16_t* short_ptr = reinterpret_cast<uint16_t*>RtlOffsetToPointer(address, offset);

        switch ( type ) {
            case IMAGE_REL_BASED_ABSOLUTE:
            break;

            case IMAGE_REL_BASED_HIGH:
            {
                *short_ptr = HIWORD(MAKELONG(0, *short_ptr) + (delta & 0x00000000FFFFFFFF));
                break;
            }

            case IMAGE_REL_BASED_LOW:
            {
                *short_ptr = *short_ptr + LOWORD(delta & 0x000000000000FFFF);
                break;
            }

            case IMAGE_REL_BASED_HIGHLOW:
            {
                auto long_ptr = reinterpret_cast<uint32_t*>RtlOffsetToPointer(address, offset);
                *long_ptr = *long_ptr + (delta & 0x00000000FFFFFFFF);
                break;
            }

            case IMAGE_REL_BASED_DIR64:
            {
                auto longlong_ptr = reinterpret_cast<uint64_t*>RtlOffsetToPointer(address, offset);
                *longlong_ptr = *longlong_ptr + delta;
                break;
            }

            case IMAGE_REL_BASED_HIGHADJ:
            case IMAGE_REL_BASED_MIPS_JMPADDR:
            default:
            {
                err << wa::showminus << __FUNCTION__ ": unsupported fixup type " << std::dec << type << " at ";
                err << std::hex << std::showbase << address << endlerr;
                return nullptr;
            }
        }

        loc_type_offset++;
    }

    return reinterpret_cast<IMAGE_BASE_RELOCATION*>(loc_type_offset);
}

bool WDbgArkPe::GetNtHeaders(const void* base, NtHeaders* nth) {
    auto header = ::ImageNtHeader(const_cast<void*>(base));

    if ( !header ) {
        std::string lasterr = LastErrorToString(GetLastError());
        err << wa::showminus << __FUNCTION__ ": ImageNtHeader failed : " << lasterr << endlerr;
        return false;
    }

    *nth = wa::GetNtHeaders(header);
    return true;
}

}   // namespace wa
