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

#include "wdbgark.hpp"

EXT_COMMAND(objtype,
            "Output kernel-mode object type(s)\n",
            "{type;s;o;type,Object type name}")
{
    string type = "";

    RequireKernelMode();

    Init();

    if ( HasArg( "type" ) ) // object type was provided
        type.assign( GetArgStr( "type" ) );

    out << "Displaying \\ObjectTypes\\" << type << endlout;

    unsigned __int64 object_types_directory_offset = m_obj_helper.FindObjectByName( "ObjectTypes", 0 );

    if ( !object_types_directory_offset )
    {
        err << "Failed to get \"ObjectTypes\" directory" << endlerr;
        return;
    }

    WDbgArkAnalyze display;
    stringstream   tmp_stream;
    display.Init( &tmp_stream, AnalyzeTypeDefault );
    display.SetOwnerModule( "nt" );
    display.PrintHeader();

    try
    {
        if ( type.empty() )
        {
            WalkDirectoryObject(object_types_directory_offset,
                                reinterpret_cast<void*>( &display ),
                                DirectoryObjectTypeCallback);
        }
        else
        {
            ExtRemoteTyped object_type("nt!_OBJECT_TYPE",
                                       m_obj_helper.FindObjectByName( type, object_types_directory_offset ),
                                       false,
                                       NULL,
                                       NULL);

            DirectoryObjectTypeCallback( this, object_type, reinterpret_cast<void*>( &display ) );
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << endlerr;
    }

    display.PrintFooter();
}

HRESULT WDbgArk::DirectoryObjectTypeCallback(WDbgArk* wdbg_ark_class, ExtRemoteTyped &object, void* context)
{
    WDbgArkAnalyze* display = reinterpret_cast<WDbgArkAnalyze*>( context );
    stringstream    loc;

    try
    {
        ExtRemoteTyped object_type( "nt!_OBJECT_TYPE", object.m_Offset, false, NULL, NULL );
        ExtRemoteTyped type_info = object_type.Field( "TypeInfo" );

        display->AnalyzeObjectTypeInfo( type_info, object );
    }
    catch( ... )
    {
        loc << "Exception in " << __FUNCTION__ << " with object.m_Offset = ";
        loc << object.m_Offset << endlerr;

        return E_UNEXPECTED;
    }

    return S_OK;
}