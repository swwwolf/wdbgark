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

#include "winapi.hpp"

#include <windows.h>
#include <string>

namespace wa {
//////////////////////////////////////////////////////////////////////////
std::string LastErrorToString(const DWORD message_error) {
    if ( !message_error ) {
        return std::string();
    }

    char* buffer = nullptr;

    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    size_t size = FormatMessage(flags,
                                nullptr,
                                message_error,
                                MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                                reinterpret_cast<LPTSTR>(&buffer),
                                0,
                                nullptr);

    std::string message(buffer, size);
    HeapFree(GetProcessHeap(), 0, buffer);
    return message;
}
//////////////////////////////////////////////////////////////////////////
bool MapImage(const std::string &path, HANDLE* file_handle, HANDLE* map_handle, void** map_address) {
    if ( !file_handle || !map_handle || !map_address ) {
        return false;
    }

    *file_handle = INVALID_HANDLE_VALUE;
    *map_handle = nullptr;
    *map_address = nullptr;

    HANDLE hfile = CreateFile(path.c_str(),
                              FILE_READ_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_SUPPORTS_SPARSE_VDL,
                              nullptr);

    if ( hfile == INVALID_HANDLE_VALUE ) {
        return false;
    }

    HANDLE hmap = CreateFileMapping(hfile, nullptr, PAGE_WRITECOPY, 0, 0, nullptr);

    if ( !hmap ) {
        UnmapImage(&hfile, nullptr, nullptr);
        return false;
    }

    void* address = MapViewOfFile(hmap, FILE_MAP_COPY, 0, 0, 0);

    if ( !address ) {
        UnmapImage(&hfile, &hmap, nullptr);
        return false;
    }

    *file_handle = hfile;
    *map_handle = hmap;
    *map_address = address;
    return true;
}
//////////////////////////////////////////////////////////////////////////
void UnmapImage(HANDLE* file_handle, HANDLE* map_handle, void** map_address) {
    if ( map_address ) {
        UnmapViewOfFile(*map_address);
        *map_address = nullptr;
    }

    if ( map_handle ) {
        CloseHandle(*map_handle);
        *map_handle = nullptr;
    }

    if ( file_handle && *file_handle != INVALID_HANDLE_VALUE ) {
        CloseHandle(*file_handle);
        *file_handle = INVALID_HANDLE_VALUE;
    }
}
//////////////////////////////////////////////////////////////////////////
}   // namespace wa
