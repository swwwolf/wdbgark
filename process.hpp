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

#ifndef _PROCESS_HPP_
#define _PROCESS_HPP_

#include <string>
#include <sstream>
#include <vector>
using namespace std;

#include <engextcpp.hpp>

class WDbgArkProcess : public ExtNtOsInformation
{
public:

    //////////////////////////////////////////////////////////////////////////
    // class typedefs
    //////////////////////////////////////////////////////////////////////////
    typedef struct ProcessInfoTag
    {
        ExtRemoteTyped   process;
        unsigned __int64 eprocess;
        string           image_file_name;
    } ProcessInfo;

    WDbgArkProcess() :
        m_inited( false ),
        current_process( 0 ) { }

    ~WDbgArkProcess()
    {
        if ( IsInited() )
        {
            m_process_list.clear();

            if ( current_process )
                g_Ext->m_System2->SetImplicitProcessDataOffset( current_process );
        }
    }

    bool Init(void);
    bool IsInited(void){ return m_inited == true; }

    unsigned __int64 FindEProcessByImageFileName(const string &process_name);
    unsigned __int64 FindEProcessAnyGUIProcess();
    HRESULT          SetImplicitProcess(unsigned __int64 set_eprocess);

private:

    bool             GetProcessImageFileName(ExtRemoteTyped &process, string& output_name);
    unsigned __int64 GetProcessDataOffset(ExtRemoteTyped &process);
    bool             FindProcessInfoByImageFileName(const string &process_name, ProcessInfo* info);

    unsigned __int64    current_process;
    vector<ProcessInfo> m_process_list;
    bool                m_inited;
    stringstream        err;
};

#endif // _PROCESS_HPP_