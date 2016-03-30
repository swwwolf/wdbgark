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

//////////////////////////////////////////////////////////////////////////
//  Include this after "#define EXT_CLASS WDbgArk" only
//////////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef SYSTEMVER_HPP_
#define SYSTEMVER_HPP_

#include <sstream>
#include <set>

#include "./ddk.h"

namespace wa {

class WDbgArkSystemVer {
 public:
    WDbgArkSystemVer();
    bool IsInited(void) const { return m_inited; }
    uint32_t GetStrictVer(void) const { return m_strict_minor_build; }
    bool IsBuildInRangeStrict(const uint32_t low, const uint32_t high) const {
        return ((m_strict_minor_build >= low) && (m_strict_minor_build <= high));
    }
    void CheckWindowsBuild(void);

 private:
     bool SetWindowsStrictMinorBuild(void);
     void InitKnownWindowsBuilds(void);

 private:
    bool m_inited = false;
    uint32_t m_platform_id = 0;
    uint32_t m_major_build = 0;
    uint32_t m_minor_build = 0;
    uint32_t m_service_pack_number = 0;
    uint32_t m_strict_minor_build = 0;
    std::set<uint32_t> m_known_windows_builds = {
        WXP_VER, W2K3_VER, VISTA_RTM_VER, VISTA_SP1_VER, VISTA_SP2_VER, W7RTM_VER, W7SP1_VER, W8RTM_VER, W81RTM_VER,
        W10RTM_VER, W10TH2_VER };
    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out{};
    std::stringstream warn{};
    std::stringstream err{};
};

}   // namespace wa

#endif  // SYSTEMVER_HPP_
