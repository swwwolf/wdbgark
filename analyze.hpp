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

#ifndef _ANALYZE_HPP_
#define _ANALYZE_HPP_

#include <string>
#include <sstream>
#include <iomanip>
using namespace std;

#include <engextcpp.hpp>
#include <bprinter/table_printer.h>

/* global stream manipulators */
inline std::ostream& endlout(std::ostream& arg)
{
    std::stringstream ss;

    arg << "\n";
    ss << arg.rdbuf();
    g_Ext->Dml( "%s", ss.str().c_str() );
    arg.flush();

    return arg;
}

inline std::ostream& endlwarn(std::ostream& arg)
{
    std::stringstream ss;

    arg << "\n";
    ss << arg.rdbuf();
    g_Ext->DmlWarn( "%s", ss.str().c_str() );
    arg.flush();

    return arg;
}

inline std::ostream& endlerr(std::ostream& arg)
{
    std::stringstream ss;

    arg << "\n";
    ss << arg.rdbuf();
    g_Ext->DmlErr( "%s", ss.str().c_str() );
    arg.flush();

    return arg;
}

//////////////////////////////////////////////////////////////////////////
// analyze, display, print routines
//////////////////////////////////////////////////////////////////////////

enum AnalyzeTypeInit
{
    AnalyzeTypeDefault,
    AnalyzeTypeCallback
};

class WDbgArkAnalyze
{
public:
    WDbgArkAnalyze() :
        m_inited(false),
        m_owner_module_inited(false)
    { }
    ~WDbgArkAnalyze()
    {
        if ( IsInited() )
            delete tp;
    }

    bool Init(std::ostream* output);
    bool Init(std::ostream* output, const AnalyzeTypeInit type);
    bool IsInited(void){ return m_inited == true; }

    void PrintHeader(void)
    {
        if ( IsInited() )
            tp->PrintHeader();
    }
    void PrintFooter(void)
    {
        if ( IsInited() )
            tp->PrintFooter();
    }
    void AddColumn(const string& header_name, int column_width)
    {
        if ( IsInited() )
            tp->AddColumn( header_name, column_width );
    }

    //////////////////////////////////////////////////////////////////////////
    // owner module routines
    //////////////////////////////////////////////////////////////////////////
    bool SetOwnerModule(void)
    {
        m_owner_module_start = 0;
        m_owner_module_end = 0;

        return m_owner_module_inited = false;
    }
    bool SetOwnerModule(const unsigned __int64 start, const unsigned __int64 end)
    {
        if ( !start || !end )
            return false;

        m_owner_module_start = start;
        m_owner_module_end = end;

        return m_owner_module_inited = true;
    }
    bool SetOwnerModule(const string &module_name);

    //////////////////////////////////////////////////////////////////////////
    // analyze routines
    //////////////////////////////////////////////////////////////////////////
    void AnalyzeAddressAsRoutine(const unsigned __int64 address,
                                 const string &type,
                                 const string &additional_info);

    void AnalyzeObjectTypeInfo(ExtRemoteTyped &type_info, ExtRemoteTyped &object);

private:

    bool                    m_inited;
    bool                    m_owner_module_inited;
    unsigned __int64        m_owner_module_start;
    unsigned __int64        m_owner_module_end;
    bprinter::TablePrinter* tp;

    //////////////////////////////////////////////////////////////////////////
    // helpers
    //////////////////////////////////////////////////////////////////////////
    HRESULT GetModuleNames(const unsigned __int64 address,
                           string &image_name,
                           string &module_name,
                           string &loaded_image_name);

    HRESULT GetNameByOffset(const unsigned __int64 address, string &name);

    bool    IsSuspiciousAddress(const unsigned __int64 address);

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    stringstream out;
    stringstream warn;
    stringstream err;
};

#endif // _ANALYZE_HPP_