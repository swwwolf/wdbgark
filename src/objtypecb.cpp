/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2017  Vyacheslav Rusakoff
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
            "{type;s,o;type;Object type name}") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    std::string type = "*";

    if ( HasArg("type") ) {
        type.assign(GetArgStr("type"));
    }

    out << wa::showplus << "Displaying callbacks registered with ObRegisterCallbacks with type " << type << endlout;

    if ( m_system_ver->GetStrictVer() <= W2K3_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    uint64_t object_types_directory_offset = m_obj_helper->FindObjectByName("ObjectTypes");

    if ( !object_types_directory_offset ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get \"ObjectTypes\" directory" << endlerr;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);
    display->PrintHeader();

    try {
        if ( type == "*" ) {
            WalkDirectoryObject(object_types_directory_offset, display.get(), DirectoryObjectTypeCallbackListCallback);
        } else {
            const auto offset = m_obj_helper->FindObjectByName(type,
                                                               object_types_directory_offset,
                                                               "\\ObjectTypes\\",
                                                               false);

            const std::string obj_type("nt!_OBJECT_TYPE");
            ExtRemoteTyped object_type(obj_type.c_str(), offset, false, m_sym_cache->GetCookieCache(obj_type), nullptr);

            if ( FAILED(DirectoryObjectTypeCallbackListCallback(this, object_type, display.get())) ) {
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
    WDbgArkAnalyzeBase* display = static_cast<WDbgArkAnalyzeBase*>(context);

    try {
        const std::string obj_type("nt!_OBJECT_TYPE");
        ExtRemoteTyped object_type(obj_type.c_str(),
                                   object.m_Offset,
                                   false,
                                   wdbg_ark_class->m_sym_cache->GetCookieCache(obj_type),
                                   nullptr);

        auto object_type_flags_typed = object_type.Field("TypeInfo").Field("ObjectTypeFlags");
        const auto size = object_type_flags_typed.GetTypeSize();

        const auto object_type_flags = static_cast<uint16_t>(object_type_flags_typed.GetData(size));

        if ( !(object_type_flags & OBJTYPE_SUPPORTS_OBJECT_CALLBACKS) ) {
            return S_OK;
        }

        display->PrintObjectDmlCmd(object);
        display->PrintFooter();

        const auto entry_common = wdbg_ark_class->m_dummy_pdb->GetShortName() + "!_OBJECT_CALLBACK_ENTRY_COMMON";
        ExtRemoteTypedList list_head(object_type.Field("CallbackList").m_Offset,
                                     entry_common.c_str(),
                                     "CallbackList",
                                     0ULL,
                                     0,
                                     wdbg_ark_class->m_sym_cache->GetCookieCache(entry_common),
                                     true);

        for ( list_head.StartHead(); list_head.HasNode(); list_head.Next() ) {
            auto callback_entry = list_head.GetTypedNode();

            display->Analyze(callback_entry.Field("PreOperation").GetPtr(), "OB_PRE_OPERATION_CALLBACK", "");
            display->Analyze(callback_entry.Field("PostOperation").GetPtr(), "OB_POST_OPERATION_CALLBACK", "");

            display->PrintFooter();
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
        return Ex.GetStatus();
    }

    return S_OK;
}

}   // namespace wa
