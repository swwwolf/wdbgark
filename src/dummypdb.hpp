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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef DUMMYPDB_HPP_
#define DUMMYPDB_HPP_

#include <engextcpp.hpp>

#include <string>
#include <sstream>

namespace wa {

class WDbgArkDummyPdb {
 public:
    WDbgArkDummyPdb();
    ~WDbgArkDummyPdb();

    bool        IsInited(void) const { return m_inited; }
    std::string GetLongName(void) const { return m_dummy_pdb_name_long; }
    std::string GetShortName(void) const { return m_dummy_pdb_name_short; }
    bool        RemoveDummyPdbModule(const ExtCheckedPointer<IDebugSymbols3> &symbols3_iface);

 private:
     bool        m_inited;
     std::string m_dummy_pdb_name_long;
     std::string m_dummy_pdb_name_short;
     std::string m_drop_path;

     bool InitDummyPdbModule(void);
    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

}   // namespace wa

#endif  // DUMMYPDB_HPP_
