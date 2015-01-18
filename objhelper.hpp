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

#include "./ddk.h"

//////////////////////////////////////////////////////////////////////////
// object manager routines
//////////////////////////////////////////////////////////////////////////
class WDbgArkObjHelper {
 public:
    WDbgArkObjHelper();

    bool IsInited(void) const { return m_inited; }

    std::pair<HRESULT, ExtRemoteTyped> GetObjectHeader(const ExtRemoteTyped &object);
    std::pair<HRESULT, ExtRemoteTyped> GetObjectHeaderNameInfo(const ExtRemoteTyped &object_header);
    std::pair<HRESULT, std::string>    GetObjectName(const ExtRemoteTyped &object);
    unsigned __int64                   FindObjectByName(const std::string &object_name,
                                                        const unsigned __int64 directory_address);

    unsigned __int64 ExFastRefGetObject(unsigned __int64 FastRef) const {
        if ( g_Ext->IsCurMachine32() )
            return FastRef & ~MAX_FAST_REFS_X86;
        else
            return FastRef & ~MAX_FAST_REFS_X64;
    }

 private:
    bool             m_inited;
    bool             object_header_old;
    unsigned __int64 ObpInfoMaskToOffset;

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

#endif  // OBJHELPER_HPP_
