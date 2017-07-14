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

#ifndef SDT_W32P_HPP_
#define SDT_W32P_HPP_

#include <string>

namespace wa {

enum ServiceTableType {
    KiServiceTable_x86 = 0,
    KiServiceTable_x64,
    W32pServiceTable_x86,
    W32pServiceTable_x64,
    W32pServiceTableFilter_x86,
    W32pServiceTableFilter_x64,
    LxpSyscalls_x64
};

enum ServiceTableIndex {
    ServiceTableXpSp3 = 0,
    ServiceTableW2k3Sp2,
    ServiceTableVistaSp0,
    ServiceTableVistaSp1,
    ServiceTableVistaSp2,
    ServiceTableW7Sp0,
    ServiceTableW7Sp1,
    ServiceTableW8Sp0,
    ServiceTableW8Sp1,
    ServiceTableW10Th1,
    ServiceTableW10Th2,
    ServiceTableW10Rs1,
    ServiceTableW10Rs2
};

std::string get_service_table_routine_name(const uint32_t minor_build,
                                           const ServiceTableType type,
                                           const uint32_t index);

}   // namespace wa

#endif  // SDT_W32P_HPP_
