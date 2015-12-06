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

#include "winapi.hpp"

#include <windows.h>
#include <string>

namespace wa {
//////////////////////////////////////////////////////////////////////////
std::string LastErrorToString(const DWORD message_error) {
    if ( !message_error )
        return std::string();

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
}   // namespace wa
