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
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"
#include "driver.hpp"
#include "whitelist.hpp"

namespace wa {

EXT_COMMAND(wa_drvmajor,
            "Output driver(s) major table",
            "{name;s,o;name;Driver full path}") {
    RequireKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    std::string name = "*";

    if ( HasArg("name") ) {
        name.assign(GetArgStr("name"));
    }

    out << wa::showplus << __FUNCTION__ << ": displaying " << name << endlout;

    auto drivers = std::make_unique<WDbgArkDriver>(m_sym_cache);

    if ( !drivers->IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": failed to initialize WDbgArkDriver" << endlerr;
        return;
    }

    WDbgArkDriver::DriversInformation drivers_info = drivers->Get();

    if ( drivers_info.empty() ) {
        err << wa::showminus << __FUNCTION__ << ": empty drivers list" << endlerr;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeDriver);

    if ( !display->AddSymbolWhiteList("nt!IopInvalidDeviceRequest", 0) ) {
        warn << wa::showqmark << __FUNCTION__ ": AddSymbolWhiteList failed" << endlwarn;
    }

    if ( m_system_ver->GetStrictVer() >= VISTA_SP2_VER && !display->AddRangeWhiteList("wdf01000") ) {
        warn << wa::showqmark << __FUNCTION__ ": AddRangeWhiteList failed" << endlwarn;
    }

    display->SetWhiteListEntries(GetDriversWhiteList());
    display->PrintHeader();

    try {
        if ( name == "*" ) {
            for ( const auto [offset, driver] : drivers_info ) {
                display->Analyze(driver);
            }
        } else {
            auto object_address = m_obj_helper->FindObjectByName(name, 0ULL, R"(\)", true);

            const std::string drv_obj("nt!_DRIVER_OBJECT");
            display->Analyze(ExtRemoteTyped(drv_obj.c_str(),
                                            object_address,
                                            false,
                                            m_sym_cache->GetCookieCache(drv_obj),
                                            nullptr));
        }
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }
}

}   // namespace wa
