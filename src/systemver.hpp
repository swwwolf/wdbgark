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

namespace wa {

class WDbgArkSystemVer {
 public:
    WDbgArkSystemVer();
    bool             IsInited(void) const { return m_inited; }
    unsigned __int32 GetStrictVer(void) const { return m_strict_minor_build; }
    bool             IsBuildInRangeStrict(const unsigned __int32 low, const unsigned __int32 high) const {
        return ((m_strict_minor_build >= low) && (m_strict_minor_build <= high));
    }

 private:
    bool                       m_inited;
    unsigned __int32           m_platform_id;
    unsigned __int32           m_major_build;
    unsigned __int32           m_minor_build;
    unsigned __int32           m_service_pack_number;
    unsigned __int32           m_strict_minor_build;
    std::set<unsigned __int32> m_known_windows_builds;
    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;

    bool SetWindowsStrictMinorBuild(void);
    void InitKnownWindowsBuilds(void);
    void CheckWindowsBuild(void);
};

}   // namespace wa

#endif  // SYSTEMVER_HPP_
