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

#include "analyze.hpp"
#include "objhelper.hpp"
#include <dbghelp.h>

bool WDbgArkAnalyze::Init(std::ostream* output)
{
    if ( IsInited() )
        return true;

    tp = new (nothrow) bprinter::TablePrinter( output );

    if ( tp )
        m_inited = true;

    return m_inited;
}

bool WDbgArkAnalyze::Init(std::ostream* output, const AnalyzeTypeInit type)
{
    if ( IsInited() )
        return true;

    tp = new (nothrow) bprinter::TablePrinter( output );

    if ( tp )
    {
        if ( type == AnalyzeTypeDefault ) // width = 180
        {
            tp->AddColumn( "Address", 18 );
            tp->AddColumn( "Name", 68 );
            tp->AddColumn( "Symbol", 68 );
            tp->AddColumn( "Module", 16 );
            tp->AddColumn( "Suspicious", 10 );

            m_inited = true;
        }
        else if ( type == AnalyzeTypeCallback ) // width = 170
        {
            tp->AddColumn( "Address", 18 );
            tp->AddColumn( "Type", 20 );
            tp->AddColumn( "Symbol", 81 );
            tp->AddColumn( "Module", 16 );
            tp->AddColumn( "Suspicious", 10 );
            tp->AddColumn( "Info", 25 );

            m_inited = true;
        }
        else if ( type == AnalyzeTypeIDT ) // width = 160
        {
            tp->AddColumn( "Address", 18 );
            tp->AddColumn( "CPU / Idx", 11 );
            tp->AddColumn( "Symbol", 80 );
            tp->AddColumn( "Module", 16 );
            tp->AddColumn( "Suspicious", 10 );
            tp->AddColumn( "Info", 25 );

            m_inited = true;
        }
    }

    return m_inited;
}

void WDbgArkAnalyze::AnalyzeAddressAsRoutine(const unsigned __int64 address,
                                             const string &type,
                                             const string &additional_info)
{
    string       symbol_name;
    string       module_name;
    string       image_name;
    string       loaded_image_name;
    stringstream module_command_buf;

    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return;
    }

    bool suspicious = IsSuspiciousAddress( address );

    if ( address )
    {
        symbol_name = "*UNKNOWN*";
        module_name = "*UNKNOWN*";

        if ( !SUCCEEDED( GetModuleNames( address, image_name, module_name, loaded_image_name ) ) )
            suspicious = true;

        module_command_buf << "<exec cmd=\"lmvm " << module_name << "\">" << std::setw( 16 ) << module_name << "</exec>";

        if ( !SUCCEEDED( GetNameByOffset( address, symbol_name ) ) )
            suspicious = true;
    }

    stringstream addr_ext;

    if ( address )
        addr_ext << "<exec cmd=\"u " << std::hex << std::showbase << address << " L5\">";

    addr_ext << std::internal << std::setw( 18 ) << std::setfill( '0' ) << std::hex << std::showbase << address;

    if ( address )
        addr_ext << "</exec>";
    
    *tp << addr_ext.str() << type << symbol_name << module_command_buf.str();

    if ( suspicious )
        *tp << "Y";        
    else
        *tp << "";

    if ( !additional_info.empty() )
        *tp << additional_info;

    if ( suspicious )
        tp->flush_warn();
    else
        tp->flush_out();
}

void WDbgArkAnalyze::AnalyzeObjectTypeInfo(ExtRemoteTyped &type_info, ExtRemoteTyped &object)
{
    string           object_name = "*UNKNOWN*";
    WDbgArkObjHelper obj_helper;

    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return;
    }

    obj_helper.Init();
    obj_helper.GetObjectName( object, object_name );

    try
    {
        stringstream object_command;
        stringstream object_name_ext;

        object_command << "<exec cmd=\"!object " << std::hex << std::showbase << object.m_Offset << "\">";
        object_command << std::hex << std::showbase << object.m_Offset << "</exec>";
        object_name_ext << object_name;

        *tp << object_command.str() << object_name_ext.str();
        tp->flush_out();
        tp->PrintFooter();

        AnalyzeAddressAsRoutine( type_info.Field( "DumpProcedure" ).GetPtr(), "DumpProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "OpenProcedure" ).GetPtr(), "OpenProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "CloseProcedure" ).GetPtr(), "CloseProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "DeleteProcedure" ).GetPtr(), "DeleteProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "ParseProcedure" ).GetPtr(), "ParseProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "SecurityProcedure" ).GetPtr(), "SecurityProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "SecurityProcedure" ).GetPtr(), "QueryNameProcedure", "" );
        tp->PrintFooter();
    }
    catch( ExtRemoteException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with type_info.m_Offset = " << type_info.m_Offset << endlerr;
    }
    */
}

HRESULT WDbgArkAnalyze::GetModuleNames(const unsigned __int64 address,
                                       string &image_name,
                                       string &module_name,
                                       string &loaded_image_name)
{
    unsigned long    len1, len2, len3 = 0;
    unsigned __int64 module_base      = 0;
    unsigned long    module_index     = 0;

    if ( !address )
        return E_INVALIDARG;

    HRESULT err = g_Ext->m_Symbols->GetModuleByOffset( address, 0, &module_index, &module_base );

    if ( SUCCEEDED( err ) )
    {
        err = g_Ext->m_Symbols->GetModuleNames(module_index,
                                               module_base,
                                               NULL,
                                               0,
                                               &len1,
                                               NULL,
                                               0,
                                               &len2,
                                               NULL,
                                               0,
                                               &len3);

        if ( SUCCEEDED( err ) )
        {
            char* buf1 = new (nothrow) char[ len1 + 1 ];
            char* buf2 = new (nothrow) char[ len2 + 1 ];
            char* buf3 = new (nothrow) char[ len3 + 1 ];

            if ( !buf1 || !buf2 || !buf3 )
            {
                if ( buf3 )
                    delete[] buf3;

                if ( buf2 )
                    delete[] buf2;

                if ( buf1 )
                    delete[] buf1;

                return E_OUTOFMEMORY;
            }

            ZeroMemory( buf1, len1 + 1 );
            ZeroMemory( buf2, len2 + 1 );
            ZeroMemory( buf3, len3 + 1 );

            err = g_Ext->m_Symbols->GetModuleNames(module_index,
                                                   module_base,
                                                   buf1,
                                                   len1 + 1,
                                                   NULL,
                                                   buf2,
                                                   len2 + 1,
                                                   NULL,
                                                   buf3,
                                                   len3 + 1,
                                                   NULL);

            if ( SUCCEEDED( err ) )
            {
                image_name = buf1;
                transform( image_name.begin(), image_name.end(), image_name.begin(), tolower );

                module_name = buf2;
                transform( module_name.begin(), module_name.end(), module_name.begin(), tolower );

                loaded_image_name = buf3;
                transform( loaded_image_name.begin(), loaded_image_name.end(), loaded_image_name.begin(), tolower );
            }

            delete[] buf3;
            delete[] buf2;
            delete[] buf1;
        }
    }

    return err;
}

HRESULT WDbgArkAnalyze::GetNameByOffset(const unsigned __int64 address, string &name)
{
    unsigned long    name_buffer_size = 0;
    unsigned __int64 displacement     = 0;
    HRESULT          err              = E_UNEXPECTED;
    stringstream     stream_name;

    if ( !address )
        return E_INVALIDARG;

    err = g_Ext->m_Symbols->GetNameByOffset( address, NULL, 0, &name_buffer_size, &displacement );

    if ( SUCCEEDED( err ) && name_buffer_size )
    {
        char* tmp_name = new (nothrow) char[ name_buffer_size + 1 ];

        if ( !tmp_name )
            return E_OUTOFMEMORY;

        ZeroMemory( tmp_name, name_buffer_size + 1 );

        err = g_Ext->m_Symbols->GetNameByOffset( address, tmp_name, name_buffer_size, NULL, NULL );

        if ( SUCCEEDED( err ) )
        {
            stream_name << tmp_name;

            if ( displacement )
                stream_name << "+" << std::hex << std::showbase << displacement;

            name = stream_name.str();
        }

        delete[] tmp_name;
    }

    return err;
}

bool WDbgArkAnalyze::SetOwnerModule(const string &module_name)
{
    if ( !IsInited() )
    {
        err << __FUNCTION__ << ": class is not initialized" << endlerr;
        return false;
    }

    try
    {
        unsigned long index = g_Ext->FindFirstModule( module_name.c_str(), NULL, 0 );

        if ( SUCCEEDED( g_Ext->m_Symbols->GetModuleByIndex( index, &m_owner_module_start ) ) )
        {
            IMAGEHLP_MODULEW64 info;
            g_Ext->GetModuleImagehlpInfo( m_owner_module_start, &info );

            m_owner_module_end = m_owner_module_start + info.ImageSize;
            m_owner_module_inited = true;

            return true;
        }
    }
    catch ( ExtStatusException Ex )
    {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    /*
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with module_name = " << module_name << endlerr;
    }
    */

    return false;
}

bool WDbgArkAnalyze::IsSuspiciousAddress(const unsigned __int64 address)
{
    if ( !m_owner_module_inited )
        return false;

    if ( !address )
        return false;

    if ( address >= m_owner_module_start && address <= m_owner_module_end )
        return false;

    return true;
}