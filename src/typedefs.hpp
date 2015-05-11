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

#ifndef TYPEDEFS_HPP_
#define TYPEDEFS_HPP_

#include <string>
#include <map>
#include <vector>

namespace wa {
    //////////////////////////////////////////////////////////////////////////
    typedef struct SystemCbCommandTag {
        std::string      list_count_name;
        std::string      list_head_name;
        unsigned __int32 offset_to_routine;
        unsigned __int64 list_count_address;
        unsigned __int64 list_head_address;
    } SystemCbCommand;

    using callbacksInfo = std::map <std::string, SystemCbCommand>;
    //////////////////////////////////////////////////////////////////////////
    typedef struct OutputWalkInfoTag {
        unsigned __int64 address;
        unsigned __int64 object_address;
        unsigned __int64 list_head_address;
        std::string      list_head_name;
        std::string      type;
        std::string      info;
    } OutputWalkInfo;

    using walkresType = std::vector<OutputWalkInfo>;
    //////////////////////////////////////////////////////////////////////////
    typedef struct WalkCallbackContextTag {
        std::string      type;
        std::string      list_head_name;
        walkresType*     output_list_pointer;
        unsigned __int64 list_head_address;
    } WalkCallbackContext;
    //////////////////////////////////////////////////////////////////////////
    typedef struct HalDispatchTableInfoTag {
        unsigned __int8 hdt_count;      // HalDispatchTable table count
        unsigned __int8 hpdt_count;     // HalPrivateDispatchTable table count
        unsigned __int8 hiommu_count;   // HalIommuDispatch table count (W8.1+)
        unsigned __int8 skip;           // Skip first N entries
    } HalDispatchTableInfo;

    using haltblInfo = std::map <unsigned __int32, HalDispatchTableInfo>;
    //////////////////////////////////////////////////////////////////////////
}   // namespace wa

#endif  // TYPEDEFS_HPP_
