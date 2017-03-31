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

#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "util.hpp"

namespace wa {

EXT_COMMAND(wdrce_copyfile,
            "Copy file (live debug only!)",
            "{path;s;path;Native file path (ANSI only or skip this argument)}") {
    RequireLiveKernelMode();

    if ( !Init() ) {
        throw ExtStatusException(S_OK, "global init failed");
    }

    if ( !m_wdrce->Init() ) {
        err << wa::showminus << __FUNCTION__ ": WDbgArkRce init failed" << endlerr;
        return;
    }

    try {
        std::wstring file_path;

        if ( HasArg("path") ) {
            file_path.assign(string_to_wstring(GetArgStr("path", false)));
        } else {
            out << wa::showplus << "Enter native file path" << endlout;

            size_t buffer_size = INT16_MAX + 1;
            std::unique_ptr<wchar_t[]> buffer = std::make_unique<wchar_t[]>(buffer_size);
            std::memset(buffer.get(), 0, buffer_size * sizeof(wchar_t));
                
            if ( FAILED(m_Control4->InputWide(buffer.get(), INT16_MAX, nullptr)) ) {
                err << wa::showminus << __FUNCTION__ ": input failed" << endlerr;
                return;
            }

            file_path.assign(buffer.release());
        }

        auto result = m_wdrce->ExecuteCopyfile(file_path);

        if ( !result ) {
            err << wa::showminus << __FUNCTION__ ": ExecuteCopyfile failed" << endlerr;
            return;
        }

        out << wa::showplus << "Hit \'go\' to continue execution" << endlout;
        WaitForGoInput();
        Execute("g;");
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch ( const ExtInvalidArgumentException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }
}

}   // namespace wa
