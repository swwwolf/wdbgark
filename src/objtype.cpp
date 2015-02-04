/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2015  Vyacheslav Rusakoff
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

#include <string>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

EXT_COMMAND(wa_objtype,
            "Output kernel-mode object type(s)",
            "{type;s;o;type,Object type name}") {
    std::string type = "*";

    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( HasArg("type") )   // object type was provided
        type.assign(GetArgStr("type"));

    out << "Displaying \\ObjectTypes\\" << type << endlout;

    unsigned __int64 object_types_directory_offset = m_obj_helper->FindObjectByName("ObjectTypes", 0);

    if ( !object_types_directory_offset ) {
        err << __FUNCTION__ << ": failed to get \"ObjectTypes\" directory" << endlerr;
        return;
    }

    std::unique_ptr<WDbgArkAnalyze> display(new WDbgArkAnalyze(WDbgArkAnalyze::AnalyzeTypeDefault));

    if ( !display->SetOwnerModule("nt") )
        warn << __FUNCTION__ ": SetOwnerModule failed" << endlwarn;

    display->PrintHeader();

    try {
        if ( type == "*" ) {
            WalkDirectoryObject(object_types_directory_offset,
                                reinterpret_cast<void*>(display.get()),
                                DirectoryObjectTypeCallback);
        } else {
            ExtRemoteTyped object_type("nt!_OBJECT_TYPE",
                                       m_obj_helper->FindObjectByName(type, object_types_directory_offset),
                                       false,
                                       NULL,
                                       NULL);

            if ( !SUCCEEDED(DirectoryObjectTypeCallback(this, object_type, reinterpret_cast<void*>(display.get()))) )
                err << __FUNCTION__ << ": DirectoryObjectTypeCallback failed" << endlerr;
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

HRESULT WDbgArk::DirectoryObjectTypeCallback(WDbgArk* wdbg_ark_class, const ExtRemoteTyped &object, void* context) {
    WDbgArkAnalyze* display = reinterpret_cast<WDbgArkAnalyze*>(context);

    try {
        ExtRemoteTyped object_type("nt!_OBJECT_TYPE", object.m_Offset, false, NULL, NULL);
        ExtRemoteTyped typeinfo = object_type.Field("TypeInfo");

        display->AnalyzeObjectTypeInfo(typeinfo, object);
    }
    catch ( const ExtRemoteException &Ex ) {
        std::stringstream tmperr;
        tmperr << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return Ex.GetStatus();
    }

    return S_OK;
}
