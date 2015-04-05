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

#include "wdbgark.hpp"
#include "colorhack.hpp"
#include "manipulators.hpp"

namespace wa {

EXT_COMMAND(wa_colorize,
            "Adjust WinDBG colors dynamically (prints info with no parameters)",
            "{enable;b;o;enable,Enable colorizing}{disable;b;o;disable,Disable colorizing}") {
    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    if ( !m_color_hack->IsInited() )
        throw ExtStatusException(S_OK, "color hack init failed");

    bool enable = HasArg("enable");
    bool disable = HasArg("disable");

    if ( enable && disable )
        throw ExtStatusException(S_OK, "42");

    if ( !enable && !disable ) {
        m_color_hack->PrintInformation();
        return;
    }

    if ( enable ) {
        if ( m_color_hack->SetTheme("default") ) {
            out << wa::showplus << "Colorizing enabled" << endlout;
        } else {
            err << wa::showminus << "Colorizing failed" << endlerr;
        }
    } else if ( disable ) {
        m_color_hack->RevertColors();
        out << wa::showplus << "Colorizing disabled" << endlout;
    }
}

}   // namespace wa
