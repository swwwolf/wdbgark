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

#include <map>
#include <sstream>
#include <memory>

#include "driver.hpp"
#include "device.hpp"
#include "symcache.hpp"
#include "manipulators.hpp"
#include "objhelper.hpp"

namespace wa {

WDbgArkDriver::WDbgArkDriver(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : m_inited(false),
      m_drivers_list(),
      m_sym_cache(sym_cache),
      m_obj_helper(new WDbgArkObjHelper(m_sym_cache)),
      err() {
    if ( !m_obj_helper->IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": failed to initialize WDbgArkObjHelper" << endlerr;
        return;
    }

    std::unique_ptr<WDbgArkDevice> devices(new WDbgArkDevice(m_sym_cache));

    if ( !devices->IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": failed to initialize WDbgArkDevice" << endlerr;
        return;
    }

    auto devices_info = devices->Get();

    if ( devices_info.empty() ) {
        err << wa::showminus << __FUNCTION__ << ": no devices found" << endlerr;
        return;
    }

    for ( auto &device : devices_info ) {
        try {
            ExtRemoteTyped driver = *device.second.Field("DriverObject");

            if ( driver.m_Offset )
                m_drivers_list.insert({ driver.m_Offset, driver });
        } catch ( const ExtRemoteException& ) {}
    }

    m_inited = true;
}

}   // namespace wa
