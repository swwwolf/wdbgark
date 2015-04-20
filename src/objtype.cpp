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

namespace wa {

EXT_COMMAND(wa_objtype,
            "Output kernel-mode object type(s)",
            "{type;s;o;type,Object type name}") {
    std::string type = "*";

    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( HasArg("type") )   // object type was provided
        type.assign(GetArgStr("type"));

    out << wa::showplus << "Displaying \\ObjectTypes\\" << type << endlout;

    auto object_types_directory_offset = m_obj_helper->FindObjectByName("ObjectTypes", 0);

    if ( !object_types_directory_offset ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get \"ObjectTypes\" directory" << endlerr;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeObjType);

    if ( !display->AddRangeWhiteList("nt") )
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;

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
                err << wa::showminus << __FUNCTION__ << ": DirectoryObjectTypeCallback failed" << endlerr;
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

HRESULT WDbgArk::DirectoryObjectTypeCallback(WDbgArk*, const ExtRemoteTyped &object, void* context) {
    WDbgArkAnalyzeBase* display = reinterpret_cast<WDbgArkAnalyzeBase*>(context);

    try {
        ExtRemoteTyped object_type("nt!_OBJECT_TYPE", object.m_Offset, false, NULL, NULL);
        ExtRemoteTyped typeinfo = object_type.Field("TypeInfo");

        display->Analyze(typeinfo, object);
    }
    catch ( const ExtRemoteException &Ex ) {
        std::stringstream tmperr;
        tmperr << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return Ex.GetStatus();
    }

    return S_OK;
}

}   // namespace wa
