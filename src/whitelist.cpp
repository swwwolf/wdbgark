/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2016  Vyacheslav Rusakoff
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
#include "analyze.hpp"

namespace wa {

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
        { "usbaudio", { "ks" } }
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
        { "virtualkey", { "registry" } }
    };
}

}   // namespace wa
