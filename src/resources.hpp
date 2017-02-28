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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef RESOURCES_HPP_
#define RESOURCES_HPP_

#include <string>
#include <sstream>

namespace wa {

class WDbgArkResHelper {
 public:
    WDbgArkResHelper();

    bool DropResource(const char* resource_name,
                      const std::string &type,
                      const std::string &file_name);

    std::string GetDropPath(void) const { return m_temp_path; }

 private:
     std::string m_main_subdir;
     std::string m_platform_subdir;
     std::string m_temp_path;

    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

}   // namespace wa

#endif  // RESOURCES_HPP_
