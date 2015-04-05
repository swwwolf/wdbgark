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

EXT_COMMAND(wa_drvmajor,
            "Output driver(s) major table",
            "{name;s;o;name,Driver object name}") {
    std::string name = "*";

    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( HasArg("name") )
        name.assign(GetArgStr("name"));

    out << wa::showplus << __FUNCTION__ << ": displaying " << name << endlout;

    auto driver_directory_offset = m_obj_helper->FindObjectByName("Driver", 0);

    if ( !driver_directory_offset ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get \"Driver\" directory" << endlerr;
        return;
    }

    auto filesystem_directory_offset = m_obj_helper->FindObjectByName("FileSystem", 0);

    if ( !filesystem_directory_offset ) {
        err << wa::showminus << __FUNCTION__ << ": failed to get \"FileSystem\" directory" << endlerr;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeDriver);

    display->PrintHeader();

    try {
        if ( name == "*" ) {
            WalkDirectoryObject(driver_directory_offset,
                                reinterpret_cast<void*>(display.get()),
                                DirectoryObjectDriverCallback);

            display->PrintFooter();

            WalkDirectoryObject(filesystem_directory_offset,
                                reinterpret_cast<void*>(display.get()),
                                DirectoryObjectDriverCallback);
        } else {
            auto object_address = m_obj_helper->FindObjectByName(name, driver_directory_offset);

            if ( !object_address )
                object_address = m_obj_helper->FindObjectByName(name, filesystem_directory_offset);

            ExtRemoteTyped driver_object("nt!_DRIVER_OBJECT", object_address, false, NULL, NULL);

            if ( !SUCCEEDED(DirectoryObjectDriverCallback(this,
                                                          driver_object,
                                                          reinterpret_cast<void*>(display.get()))))
                err << wa::showminus << __FUNCTION__ << ": DirectoryObjectDriverCallback failed" << endlerr;
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }
}

HRESULT WDbgArk::DirectoryObjectDriverCallback(WDbgArk* wdbg_ark_class, const ExtRemoteTyped &object, void* context) {
    WDbgArkAnalyzeBase* display = reinterpret_cast<WDbgArkAnalyzeBase*>(context);

    try {
        auto result_type_name = wdbg_ark_class->m_obj_helper->GetObjectTypeName(object);

        if ( SUCCEEDED(result_type_name.first) && result_type_name.second == "Driver" ) {
            ExtRemoteTyped driver_object("nt!_DRIVER_OBJECT", object.m_Offset, false, NULL, NULL);
            display->Analyze(driver_object);
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
