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
#include <sstream>
#include <memory>
#include <utility>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {

EXT_COMMAND(wa_objtypecb,
            "Output kernel-mode callbacks registered with ObRegisterCallbacks",
            "{type;s;o;type,Object type name}") {
    std::string type = "*";

    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( HasArg("type") )   // object type was provided
        type.assign(GetArgStr("type"));

    out << wa::showplus << "Displaying callbacks registered with ObRegisterCallbacks with type " << type << endlout;

    if ( m_system_ver->GetStrictVer() <= W2K3_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    unsigned __int64 object_types_directory_offset = m_obj_helper->FindObjectByName("ObjectTypes");

    if ( !object_types_directory_offset ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get \"ObjectTypes\" directory" << endlerr;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);
    display->PrintHeader();

    try {
        if ( type == "*" ) {
            WalkDirectoryObject(object_types_directory_offset,
                                reinterpret_cast<void*>(display.get()),
                                DirectoryObjectTypeCallbackListCallback);
        } else {
            ExtRemoteTyped object_type("nt!_OBJECT_TYPE",
                                       m_obj_helper->FindObjectByName(type,
                                                                      object_types_directory_offset,
                                                                      "\\ObjectTypes\\",
                                                                      false),
                                       false,
                                       NULL,
                                       NULL);

            if ( !SUCCEEDED(DirectoryObjectTypeCallbackListCallback(this,
                                                                    object_type,
                                                                    reinterpret_cast<void*>(display.get()))) ) {
                err << wa::showminus << __FUNCTION__ << ": DirectoryObjectTypeCallbackListCallback failed" << endlerr;
            }
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

HRESULT WDbgArk::DirectoryObjectTypeCallbackListCallback(WDbgArk* wdbg_ark_class,
                                                         const ExtRemoteTyped &object,
                                                         void* context) {
    WDbgArkAnalyzeBase* display = reinterpret_cast<WDbgArkAnalyzeBase*>(context);

    try {
        ExtRemoteTyped object_type("nt!_OBJECT_TYPE", object.m_Offset, false, NULL, NULL);
        unsigned __int8 object_type_flags = object_type.Field("TypeInfo").Field("ObjectTypeFlags").GetUchar();

        if ( !(object_type_flags & OBJTYPE_SUPPORTS_OBJECT_CALLBACKS) )
            return S_OK;

        display->PrintObjectDmlCmd(object);
        display->PrintFooter();

        std::string dummy_pdb_callback_entry_common = wdbg_ark_class->m_dummy_pdb->GetShortName() +\
            "!_OBJECT_CALLBACK_ENTRY_COMMON";

        ExtRemoteTypedList list_head(object_type.Field("CallbackList").m_Offset,
                                     dummy_pdb_callback_entry_common.c_str(),
                                     "CallbackList",
                                     0ULL,
                                     0,
                                     nullptr,
                                     true);

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
            ExtRemoteTyped callback_entry = list_head.GetTypedNode();

            display->Analyze(callback_entry.Field("PreOperation").GetPtr(), "OB_PRE_OPERATION_CALLBACK", "");
            display->Analyze(callback_entry.Field("PostOperation").GetPtr(), "OB_POST_OPERATION_CALLBACK", "");

            display->PrintFooter();
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        std::stringstream tmperr;
        tmperr << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return Ex.GetStatus();
    }

    return S_OK;
}

}   // namespace wa
