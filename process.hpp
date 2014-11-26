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
#include <vector>
#include <algorithm>

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

    WDbgArkProcess()
    {
        ExtRemoteTypedList list_head = GetKernelProcessList();

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() )
        {
            ProcessInfo info;

            info.process = list_head.GetTypedNode();
            info.eprocess = GetProcessDataOffset( info.process );
            info.image_file_name = GetProcessImageFileName( info.process );
            transform( info.image_file_name.begin(), info.image_file_name.end(), info.image_file_name.begin(), tolower );

            m_process_list.push_back( info );
        }
    }

    ~WDbgArkProcess()
    {
        m_process_list.clear();
    }

    unsigned __int64 FindEProcessByImageFileName(const string &process_name)
    {
        ProcessInfo info;

        if ( FindProcessInfoByImageFileName( process_name, &info ) )
            return info.eprocess;

        return 0;
    }

private:

    string GetProcessImageFileName(ExtRemoteTyped &process)
    {
        char buffer[100] = { 0 };

        ExtRemoteTyped image_file_name = process.Field( "ImageFileName" );
        return image_file_name.GetString( buffer, 100, image_file_name.GetTypeSize(), false );
    }

    unsigned __int64 GetProcessDataOffset(ExtRemoteTyped &process)
    {
        return process.m_Offset;
    }

    bool FindProcessInfoByImageFileName(const string &process_name, ProcessInfo* info)
    {
        string compare_with = process_name;
        transform( compare_with.begin(), compare_with.end(), compare_with.begin(), tolower );

        for ( vector<ProcessInfo>::iterator it = m_process_list.begin(); it != m_process_list.end(); ++it )
        {
            if ( compare_with == (*it).image_file_name )
            {
                *info = *it;
                return true;
            }
        }

        return false;
    }

    vector<ProcessInfo> m_process_list;
};

#endif // _PROCESS_HPP_