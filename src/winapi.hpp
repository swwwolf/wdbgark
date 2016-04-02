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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef WINAPI_HPP_
#define WINAPI_HPP_

#include <windows.h>
#include <string>

namespace wa {

std::string LastErrorToString(const DWORD message_error);
bool MapImage(const std::string &path, HANDLE* file_handle, HANDLE* map_handle, void** map_address);
void UnmapImage(HANDLE* file_handle, HANDLE* map_handle, void** map_address);

}   // namespace wa

#endif  // WINAPI_HPP_
