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

#include "whitelist.hpp"

#include <dbghelp.h>

#include <string>
#include <algorithm>

#include "manipulators.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
bool WDbgArkAnalyzeWhiteList::AddRangeWhiteListInternal(const std::string &module_name, Ranges* ranges) {
    try {
        uint64_t module_start = 0;
        HRESULT result = g_Ext->m_Symbols3->GetModuleByModuleName2(module_name.c_str(),
                                                                   0UL,
                                                                   0UL,
                                                                   nullptr,
                                                                   &module_start);

        if ( SUCCEEDED(result) ) {
            IMAGEHLP_MODULEW64 info;
            g_Ext->GetModuleImagehlpInfo(module_start, &info);
            ranges->insert(std::make_pair(module_start, module_start + info.ImageSize));
            return true;
        }
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkAnalyzeWhiteList::AddSymbolWhiteListInternal(const std::string &symbol_name,
                                                         const uint32_t size,
                                                         Ranges* ranges) {
    uint64_t symbol_offset = 0;

    if ( !m_sym_cache->GetSymbolOffset(symbol_name, true, &symbol_offset) )
        return false;

    ranges->insert(std::make_pair(symbol_offset, symbol_offset + size));
    return true;
}
//////////////////////////////////////////////////////////////////////////
void WDbgArkAnalyzeWhiteList::AddTempWhiteList(const std::string &name) {
    try {
        if ( !m_wl_entries.empty() ) {
            std::string search_name = name;
            std::transform(search_name.begin(), search_name.end(), search_name.begin(), tolower);

            auto entry_list = m_wl_entries.at(search_name);

            for ( auto &entry : entry_list )
                AddTempRangeWhiteList(entry);
        }
    } catch ( const std::out_of_range& ) {}
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArkAnalyzeWhiteList::IsAddressInWhiteList(const uint64_t address) const {
    if ( m_ranges.empty() && m_temp_ranges.empty() )
        return true;

    auto it = std::find_if(m_ranges.begin(),
                           m_ranges.end(),
                           [address](const Range &range) {
        return ((address >= range.first) && (address <= range.second)); });

    if ( it != m_ranges.end() )
        return true;

    auto temp_it = std::find_if(m_temp_ranges.begin(),
                                m_temp_ranges.end(),
                                [address](const Range &range) {
        return ((address >= range.first) && (address <= range.second)); });

    if ( temp_it != m_temp_ranges.end() )
        return true;

    return false;
}
//////////////////////////////////////////////////////////////////////////
WDbgArkAnalyzeWhiteList::WhiteListEntries GetDriversWhiteList() {
    return {
        { "intelide", { "pciidex" } },
        { "pciide", { "pciidex" } },
        { "atapi", { "ataport" } },
        { "pnpmanager", { "nt" } },
        { "wmixwdm", { "nt" } },
        { "acpi_hal", { "hal" } },
        { "cdrom", { "wdf01000", "classpnp" } },
        { "basicdisplay", { "dxgkrnl" } },
        { "basicrender", { "dxgkrnl" } },
        { "raw", { "nt" } },
        { "ntfs", { "nt" } },
        { "lsi_sas", { "storport" } },
        { "lsi_scsi", { "storport" } },
        { "fileinfo", { "fltmgr" } },
        { "storahci", { "storport" } },
        { "disk", { "classpnp" } },
        { "vwififlt", { "ndis" } },
        { "psched", { "ndis" } },
        { "vm3dmp", { "dxgkrnl" } },
        { "fastfat", { "nt" } },
        { "e1iexpress", { "ndis" } },
        { "usbehci", { "usbport" } },
        { "usbuhci", { "usbport" } },
        { "hdaudaddservice", { "ks", "portcls" } },
        { "hidusb", { "hidclass" } },
        { "tunnel", { "ndis" } },
        { "softwaredevice", { "nt" } },
        { "deviceapi", { "nt" } },
        { "raspppoe", { "ndis" } },
        { "rassstp", { "ndis" } },
        { "rasagilevpn", { "ndis" } },
        { "rasl2tp", { "ndis" } },
        { "ndiswan", { "ndis" } },
        { "e1g60", { "ndis" } },
        { "pptpminiport", { "ndis" } },
        { "rdprefmp", { "videoprt" } },
        { "rdpencdd", { "videoprt" } },
        { "vgasave", { "videoprt" } },
        { "rdpcdd", { "videoprt" } },
        { "cng", { "storport" } },
        { "rdpdr", { "rdbss" } },
        { "netvsc", { "ndis" } },
        { "synthvid", { "videoprt" } },
        { "vmbushid", { "hidclass" } },
        { "verifier_filter", { "nt" } },
        { "sfilter", { "ndis" } },
        { "storvsc", { "storport" } },
        { "asyncmac", { "ndis" } },
        { "raspti", { "ndis" } },
        { "mrxsmb", { "rdbss" } },
        { "mnmdd", { "videoprt" } },
        { "mshidkmdf", { "hidclass" } },
        { "cdfs", { "nt" } },
        { "iscsiprt", { "storport" } },
        { "tunmp", { "ndis" } },
        { "verifier_ddi", { "nt" } },
        { "iastorav", { "storport" } },
        { "bthpan", { "ndis" } },
        { "bthusb", { "bthport" } },
        { "usbvideo", { "ks" } },
        { "bcm43xx", { "ndis" } },
        { "b57nd60a", { "ndis" } },
        { "nativewifip", { "ndis" } },
        { "vmsp", { "ndis" } },
        { "lxss", { "lxcore" } },
        { "usbaudio", { "ks" } },
        { "wscvreg", { "nt" } }
    };
}

WDbgArkAnalyzeWhiteList::WhiteListEntries GetObjectTypesWhiteList() {
    return {
        { "tmtm", { "tm" } },
        { "tmtx", { "tm" } },
        { "tmen", { "tm" } },
        { "tmrm", { "tm" } },
        { "dmadomain", { "hal" } },
        { "dmaadapter", { "hal" } },
        { "dxgksharedresource", { "dxgkrnl" } },
        { "dxgksharedsyncobject", { "dxgkrnl" } },
        { "dxgksharedswapchainobject", { "dxgkrnl" } },
        { "networknamespace", { "ndis" } },
        { "pcwobject", { "pcw" } },
        { "filterconnectionport", { "fltmgr" } },
        { "filtercommunicationport", { "fltmgr" } },
        { "virtualkey", { "registry" } },
        { "ndiscmstate", { "ndis" } }
    };
}

}   // namespace wa
