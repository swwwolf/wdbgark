/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2014  Vyacheslav Rusakoff
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

#ifndef PROCESS_HPP_
#define PROCESS_HPP_

#include <string>
#include <sstream>
#include <vector>

#include <engextcpp.hpp>
#include "manipulators.hpp"

class WDbgArkProcess
{
 public:

    //////////////////////////////////////////////////////////////////////////
    // class typedefs
    //////////////////////////////////////////////////////////////////////////
    typedef struct ProcessInfoTag
    {
        ExtRemoteTyped   process;
        unsigned __int64 eprocess;
        std::string      image_file_name;
    } ProcessInfo;

    WDbgArkProcess();

    ~WDbgArkProcess() {
        try {
            m_process_list.clear();

            if ( m_current_process )
                if ( !SUCCEEDED(g_Ext->m_System2->SetImplicitProcessDataOffset(m_current_process)) )
                    err << __FUNCTION__ << ": failed to revert" << endlerr;
        }
        catch( ... ) {}
    }

    bool IsInited(void) const { return m_inited; }

    unsigned __int64 FindEProcessByImageFileName(const std::string &process_name);
    unsigned __int64 FindEProcessAnyGUIProcess();
    HRESULT          SetImplicitProcess(const unsigned __int64 set_eprocess);
    
 private:

    std::pair<bool, std::string> GetProcessImageFileName(const ExtRemoteTyped &process);
    unsigned __int64             GetProcessDataOffset(const ExtRemoteTyped &process) { return process.m_Offset; }
    bool                         FindProcessInfoByImageFileName(const std::string &process_name, ProcessInfo* info);

    bool                     m_inited;
    unsigned __int64         m_current_process;
    std::vector<ProcessInfo> m_process_list;
    
    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

#endif // PROCESS_HPP_