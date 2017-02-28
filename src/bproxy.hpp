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

#ifndef BPROXY_HPP_
#define BPROXY_HPP_

#include <bprinter/table_printer.h>

#include <string>
#include <sstream>
#include <memory>

namespace wa {
//////////////////////////////////////////////////////////////////////////
// proxy bprinter class
//////////////////////////////////////////////////////////////////////////
class WDbgArkBPProxy {
 public:
     virtual ~WDbgArkBPProxy() {}

     virtual void PrintHeader(void) { m_tp->PrintHeader(); }
     virtual void PrintFooter(void) { m_tp->PrintFooter(); }
     virtual void AddColumn(const std::string &header_name, const int column_width) {
         m_tp->AddColumn(header_name, column_width);
     }
     virtual void FlushOut(void) { m_tp->flush_out(); }
     virtual void FlushWarn(void) { m_tp->flush_warn(); }
     virtual void FlushErr(void) { m_tp->flush_err(); }

     template<typename T> WDbgArkBPProxy& operator<<(T input) {
         *m_tp << input;
         return *this;
     }

 protected:
    std::stringstream m_bprinter_out{};
    std::unique_ptr<bprinter::TablePrinter> m_tp = std::make_unique<bprinter::TablePrinter>(&m_bprinter_out);
};

}   // namespace wa

#endif  // BPROXY_HPP_
