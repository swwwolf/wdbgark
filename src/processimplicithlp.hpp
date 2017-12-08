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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef PROCESSIMPLICITHLP_HPP_
#define PROCESSIMPLICITHLP_HPP_

#include <engextcpp.hpp>
#include <comip.h>

#include <string>

#include "manipulators.hpp"

namespace wa {

class WDbgArkRemoteTypedProcess;    // forward declaration

class WDbgArkImplicitProcess {
 public:
    WDbgArkImplicitProcess() {
        if ( FAILED(g_Ext->m_Client->QueryInterface(__uuidof(IDebugSystemObjects2),
                                                    reinterpret_cast<void**>(&m_system2))) ) {
            err << wa::showminus << __FUNCTION__ << ": Failed to initialize interface" << endlerr;
        }
    }

    virtual ~WDbgArkImplicitProcess() {
        RevertImplicitProcess();
    }

 protected:
    bool IsSet() const { return m_revert_process != 0ULL; }

    HRESULT SetImplicitProcess(const uint64_t process_offset) {
        if ( !process_offset ) {
            return E_INVALIDARG;
        }

        uint64_t cur_process = 0ULL;
        auto result = m_system2->GetImplicitProcessDataOffset(&cur_process);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get current process offset" << endlerr;
            return result;
        }

        // already in process
        if ( cur_process == process_offset ) {
            return S_OK;
        }

        if ( IsSet() ) {
            return E_INVALIDARG;
        }

        result = m_system2->SetImplicitProcessDataOffset(process_offset);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to set implicit process to ";
            err << std::hex << std::showbase << process_offset << endlerr;
        } else {
            m_revert_process = cur_process;
            m_cur_process = process_offset;
        }

        return result;
    }

    HRESULT SetImplicitProcess(const WDbgArkRemoteTypedProcess &process);

    HRESULT RevertImplicitProcess() {
        HRESULT result = E_NOT_SET;

        if ( IsSet() ) {
            result = m_system2->SetImplicitProcessDataOffset(m_revert_process);

            if ( !SUCCEEDED(result) ) {
                err << wa::showminus << __FUNCTION__ << ": failed to revert" << endlerr;
            } else {
                m_revert_process = 0ULL;
                m_cur_process = 0ULL;
            }
        }

        return result;
    }

 protected:
    using IDebugSystemObjects2Ptr = _com_ptr_t<_com_IIID<IDebugSystemObjects2, &__uuidof(IDebugSystemObjects2)>>;

    uint64_t m_revert_process = 0ULL;
    uint64_t m_cur_process = 0ULL;
    IDebugSystemObjects2Ptr m_system2{ nullptr };
};

}   // namespace wa

#endif  // PROCESSIMPLICITHLP_HPP_
