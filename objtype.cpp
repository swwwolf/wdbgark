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

#include "wdbgark.h"

EXT_COMMAND(objtype,
            "Output the kernel-mode object type(s)\n",
            "{type;s;o;type,Object type name}")
{
    string type = "";

    RequireKernelMode();

    Init();

    if ( HasArg( "type" ) ) // object type was provided
    {
        type.assign( GetArgStr( "type" ) );
    }

    unsigned __int64 object_types_directory_offset = FindObjectByName( "ObjectTypes", 0 );

    if ( !object_types_directory_offset )
    {
        err << "Failed to get \"ObjectTypes\" directory" << endlerr;
        return;
    }

    out << "******" << endlout;
    out << "*    ";
    out << std::left << std::setw( 16 ) << "Address" << std::right << std::setw( 6 ) << ' ';
    out << std::left << std::setw( 40 ) << "Object type/Routine type" << std::right << std::setw( 12 ) << ' ';
    out << std::left << std::setw( 70 ) << "Symbol" << std::right << std::setw( 4 ) << ' ';
    out << std::left << std::setw( 30 ) << "Module" << std::right << std::setw( 1 ) << ' ';
    out << "*" << endlout;
    out << "******" << endlout;

    try
    {
        if ( type.empty() )
        {
            WalkDirectoryObject( object_types_directory_offset, NULL, DirectoryObjectTypeCallback );
        }
        else
        {
            ExtRemoteTyped object_type("nt!_OBJECT_TYPE",
                                       FindObjectByName( type, object_types_directory_offset ),
                                       false,
                                       NULL,
                                       NULL);

            DirectoryObjectTypeCallback( this, object_type, NULL );
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << endlerr;
    }

    out << "******" << endlout;
}

HRESULT WDbgArk::DirectoryObjectTypeCallback(WDbgArk* wdbg_ark_class, ExtRemoteTyped &object, void* context)
{
    string object_name = "Unknown name";

    try
    {
        if ( FAILED( wdbg_ark_class->GetObjectName( object, object_name ) ) )
        {
            wdbg_ark_class->warn << "Failed to get object name" << endlwarn;
        }

        wdbg_ark_class->out << "*    ";
        wdbg_ark_class->out << "<exec cmd=\"!object " << std::hex << std::showbase << object.m_Offset << "\">";
        wdbg_ark_class->out << std::hex << std::showbase << object.m_Offset << "</exec>";
        wdbg_ark_class->out << std::right << std::setw( 4 ) << ' ' << "<b>" << object_name << "</b>" << endlout;

        ExtRemoteTyped object_type( "nt!_OBJECT_TYPE", object.m_Offset, false, NULL, NULL );
        ExtRemoteTyped type_info = object_type.Field( "TypeInfo" );

        wdbg_ark_class->AnalyzeObjectTypeInfo( type_info );
    }
    catch( ... )
    {
        wdbg_ark_class->err << "Exception in " << __FUNCTION__ << " with object.m_Offset = ";
        wdbg_ark_class->err << object.m_Offset << endlerr;

        return E_UNEXPECTED;
    }

    return S_OK;
}

void WDbgArk::AnalyzeObjectTypeInfo(ExtRemoteTyped &type_info)
{
    try
    {
        AnalyzeAddressAsRoutine( type_info.Field( "DumpProcedure" ).GetPtr(), "DumpProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "OpenProcedure" ).GetPtr(), "OpenProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "CloseProcedure" ).GetPtr(), "CloseProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "DeleteProcedure" ).GetPtr(), "DeleteProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "ParseProcedure" ).GetPtr(), "ParseProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "SecurityProcedure" ).GetPtr(), "SecurityProcedure", "" );
        AnalyzeAddressAsRoutine( type_info.Field( "SecurityProcedure" ).GetPtr(), "QueryNameProcedure", "" );
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << " with type_info.m_Offset = " << type_info.m_Offset << endlerr;
    }
}