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

#include <string>

#include "manipulators.hpp"

namespace wa {

class WDbgArkRemoteTypedProcess;    // forward declaration

class WDbgArkImplicitProcess {
 public:
    WDbgArkImplicitProcess() {
        g_Ext->m_Client->QueryInterface(__uuidof(IDebugSystemObjects2), reinterpret_cast<void**>(&m_System2));
    }

    virtual ~WDbgArkImplicitProcess() {
        RevertImplicitProcess();

        if ( m_System2.IsSet() ) {
            EXT_RELEASE(m_System2);
        }
    }

 protected:
    HRESULT SetImplicitProcess(const uint64_t process_offset) {
        if ( !process_offset ) {
            return E_INVALIDARG;
        }

        if ( m_old_process != 0ULL ) {
            return E_INVALIDARG;
        }

        auto result = m_System2->GetImplicitProcessDataOffset(&m_old_process);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get current process offset" << endlerr;
            return result;
        }

        // already in process
        if ( m_old_process == process_offset ) {
            return S_OK;
        }

        result = m_System2->SetImplicitProcessDataOffset(process_offset);

        if ( !SUCCEEDED(result) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to set implicit process to ";
            err << std::hex << std::showbase << process_offset << endlerr;
        }

        return result;
    }

    HRESULT SetImplicitProcess(const WDbgArkRemoteTypedProcess &process);

    HRESULT RevertImplicitProcess() {
        HRESULT result = E_NOT_SET;

        if ( m_old_process != 0ULL ) {
            result = m_System2->SetImplicitProcessDataOffset(m_old_process);

            if ( !SUCCEEDED(result) ) {
                err << wa::showminus << __FUNCTION__ << ": failed to revert" << endlerr;
            } else {
                m_old_process = 0ULL;
            }
        }

        return result;
    }

 protected:
    uint64_t m_old_process = 0ULL;
    ExtCheckedPointer<IDebugSystemObjects2> m_System2{ "The extension did not initialize properly." };
};

}   // namespace wa

#endif  // PROCESSIMPLICITHLP_HPP_
