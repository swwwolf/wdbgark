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

#include "device.hpp"
#include "symcache.hpp"
#include "manipulators.hpp"
#include "objhelper.hpp"

namespace wa {

WDbgArkDevice::WDbgArkDevice(const std::shared_ptr<WDbgArkSymCache> &sym_cache)
    : m_inited(false),
      m_devices_list(),
      m_sym_cache(sym_cache),
      m_obj_helper(new WDbgArkObjHelper(m_sym_cache)),
      err() {
    if ( !m_obj_helper->IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": failed to initialize WDbgArkObjHelper" << endlerr;
        return;
    }

    auto info = m_obj_helper->GetObjectsInfo(0ULL, "\\", true);

    if ( FAILED(info.first) ) {
        err << wa::showminus << __FUNCTION__ << ": GetObjectsInfo failed" << endlerr;
        return;
    }

    for ( auto object_info : info.second ) {
        if ( object_info.second.type_name == "Device" ) {
            m_devices_list[object_info.first] = ExtRemoteTyped("nt!_DEVICE_OBJECT",
                                                               object_info.first,  // offset
                                                               false,
                                                               nullptr,
                                                               nullptr);
        }
    }

    if ( m_devices_list.empty() ) {
        err << wa::showminus << __FUNCTION__ << ": no devices found" << endlerr;
        return;
    }

    for ( auto device : m_devices_list ) {
        try {
            // loop "attached to" field and "next" fields
            ExtRemoteTyped attached_to = *device.second.Field("DeviceObjectExtension").Field("AttachedTo");
            while ( attached_to.m_Offset ) {
                m_devices_list[attached_to.m_Offset] = attached_to;

                ExtRemoteTyped next_device_to = *attached_to.Field("NextDevice");

                while ( next_device_to.m_Offset ) {
                    m_devices_list[next_device_to.m_Offset] = next_device_to;
                    next_device_to = *next_device_to.Field("NextDevice");
                }

                attached_to = *attached_to.Field("DeviceObjectExtension").Field("AttachedTo");
            }

            // loop "attached" field and "next" fields
            ExtRemoteTyped attached_device = *device.second.Field("AttachedDevice");
            while ( attached_device.m_Offset ) {
                m_devices_list[attached_device.m_Offset] = attached_device;

                ExtRemoteTyped next_device_attached = *attached_device.Field("NextDevice");

                while ( next_device_attached.m_Offset ) {
                    m_devices_list[next_device_attached.m_Offset] = next_device_attached;
                    next_device_attached = *next_device_attached.Field("NextDevice");
                }

                attached_device = *attached_device.Field("AttachedDevice");
            }

            // loop "next" fields
            ExtRemoteTyped next_device = *device.second.Field("NextDevice");
            while ( next_device.m_Offset ) {
                m_devices_list[next_device.m_Offset] = next_device;
                next_device = *next_device.Field("NextDevice");
            }
        } catch ( const ExtRemoteException& ) {}
    }

    m_inited = true;
}

}   // namespace wa
