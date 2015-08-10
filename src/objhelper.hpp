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

#ifndef OBJHELPER_HPP_
#define OBJHELPER_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>
#include <utility>
#include <map>

#include "./ddk.h"
#include "symcache.hpp"

namespace wa {

//////////////////////////////////////////////////////////////////////////
// object manager routines
//////////////////////////////////////////////////////////////////////////
class WDbgArkObjHelper {
 public:
    typedef struct ObjectInfoTag {
        ExtRemoteTyped object;
        ExtRemoteTyped directory_object;
        std::string    full_path;
        std::string    obj_name;
        std::string    type_name;
    } ObjectInfo;

    using ObjectsInformation = std::map<unsigned __int64, ObjectInfo>;  // offset : object information

 public:
    explicit WDbgArkObjHelper(const std::shared_ptr<WDbgArkSymCache> &sym_cache);
    WDbgArkObjHelper() = delete;

    bool IsInited(void) const { return m_inited; }

    std::pair<HRESULT, ExtRemoteTyped> GetObjectHeader(const ExtRemoteTyped &object);
    std::pair<HRESULT, std::string> GetObjectName(const ExtRemoteTyped &object);
    std::pair<HRESULT, ExtRemoteTyped> GetObjectType(const ExtRemoteTyped &object);
    std::pair<HRESULT, std::string> GetObjectTypeName(const ExtRemoteTyped &object);
    std::pair<HRESULT, ObjectsInformation> GetObjectsInfo(const unsigned __int64 directory_address = 0ULL,
                                                          const std::string &root_path = "\\",
                                                          const bool recursive = false);
    unsigned __int64 FindObjectByName(const std::string &object_name,
                                      const unsigned __int64 directory_address = 0ULL,
                                      const std::string &root_path = "\\",
                                      const bool recursive = false);

    unsigned __int64 ExFastRefGetObject(unsigned __int64 FastRef) const {
        if ( g_Ext->IsCurMachine32() )
            return FastRef & ~MAX_FAST_REFS_X86;
        else
            return FastRef & ~MAX_FAST_REFS_X64;
    }

 private:
    std::pair<HRESULT, ExtRemoteTyped> GetObjectHeaderNameInfo(const ExtRemoteTyped &object_header);

 private:
    bool                             m_inited;
    bool                             m_object_header_old;
    unsigned __int64                 m_ObpInfoMaskToOffset;
    unsigned __int64                 m_ObTypeIndexTableOffset;
    unsigned __int8                  m_ObHeaderCookie;
    std::shared_ptr<WDbgArkSymCache> m_sym_cache;
    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

}   // namespace wa

#endif  // OBJHELPER_HPP_
