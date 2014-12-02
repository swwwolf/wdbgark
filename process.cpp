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

#include <algorithm>
using namespace std;

#include "process.hpp"
#include "wdbgark.hpp"
#include "manipulators.hpp"

bool WDbgArkProcess::Init(void)
{
    if ( IsInited() )
        return true;

    try
    {
        ExtRemoteTypedList list_head = GetKernelProcessList();

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() )
        {
            ProcessInfo info;

            info.process = list_head.GetTypedNode();
            info.eprocess = GetProcessDataOffset( info.process );

            if ( !GetProcessImageFileName( info.process, info.image_file_name ) )
            {
                err << "Failed to read process file name ";
                err << std::hex << std::showbase << info.process.m_Offset << endlwarn;
            }
            else
            {
                transform(info.image_file_name.begin(),
                          info.image_file_name.end(),
                          info.image_file_name.begin(),
                          tolower);
            }

            m_process_list.push_back( info );
        }

        if ( !m_process_list.empty() )
            m_inited = true;
    }
    catch( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return m_inited;
}

unsigned __int64 WDbgArkProcess::FindEProcessByImageFileName(const string &process_name)
{
    ProcessInfo info;

    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return 0;
    }

    if ( FindProcessInfoByImageFileName( process_name, &info ) )
        return info.eprocess;

    return 0;
}

unsigned __int64 WDbgArkProcess::FindEProcessAnyGUIProcess()
{
    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return 0;
    }

    try
    {
        for ( vector<ProcessInfo>::iterator it = m_process_list.begin(); it != m_process_list.end(); ++it )
        {
            if ( (*it).process.Field( "Win32Process" ).GetPtr() )
                return (*it).eprocess;
        }
    }
    catch( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return 0;
}

HRESULT WDbgArkProcess::SetImplicitProcess(unsigned __int64 set_eprocess)
{
    HRESULT error;

    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return E_UNEXPECTED;
    }

    if ( !set_eprocess )
    {
        err << __FUNCTION__ << ": invalid parameter" << endlerr;
        return E_INVALIDARG;
    }

    if ( !SUCCEEDED( error = g_Ext->m_System2->GetImplicitProcessDataOffset( &current_process ) ) )
    {
        err << __FUNCTION__ << ": failed to get current EPROCESS" << endlerr;
        return error;
    }

    if ( current_process == set_eprocess )
        return S_OK;

    if ( !SUCCEEDED( error = g_Ext->m_System2->SetImplicitProcessDataOffset( set_eprocess ) ) )
    {
        err << __FUNCTION__ << ": failed to set implicit process to ";
        err << std::hex << std::showbase << set_eprocess << endlerr;
    }

    return error;
}

bool WDbgArkProcess::GetProcessImageFileName(ExtRemoteTyped &process, string& output_name)
{
    char buffer[100] = { 0 };

    try
    {
        ExtRemoteTyped image_file_name = process.Field( "ImageFileName" );
        output_name = image_file_name.GetString( buffer, 100, image_file_name.GetTypeSize(), false );
        return true;
    }
    catch( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return false;
}

unsigned __int64 WDbgArkProcess::GetProcessDataOffset(ExtRemoteTyped &process)
{
    return process.m_Offset;
}

bool WDbgArkProcess::FindProcessInfoByImageFileName(const string &process_name, ProcessInfo* info)
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