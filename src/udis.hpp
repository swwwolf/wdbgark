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

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef UDIS_HPP_
#define UDIS_HPP_

#include <udis86.h>

#include <memory>
#include <sstream>

namespace wa {

#define MAX_INSN_LENGTH 15

//////////////////////////////////////////////////////////////////////////
// Udis86 class
//////////////////////////////////////////////////////////////////////////
class WDbgArkUdis {
 public:
    WDbgArkUdis();
    WDbgArkUdis(unsigned __int8 mode, unsigned __int64 address, size_t size);
    ~WDbgArkUdis() {}

    bool IsInited(void) const { return m_inited; }
    const ud_t Get(void) const { return m_udis_obj; }
    void SwitchMode(const unsigned __int8 mode) { return ud_set_mode(&m_udis_obj, mode); }
    void SetInstructionPointer(const unsigned __int64 ip) { return ud_set_pc(&m_udis_obj, ip); }
    unsigned __int32 Disassemble(void) { return ud_disassemble(&m_udis_obj); }
    unsigned __int32 InstructionLength(void) { return ud_insn_len(&m_udis_obj); }
    unsigned __int64 InstructionOffset(void) { return ud_insn_off(&m_udis_obj); }
    const char* InstructionHex(void) { return ud_insn_hex(&m_udis_obj); }
    const unsigned __int8* InstructionPointer(void) { return ud_insn_ptr(&m_udis_obj); }
    const char* InstructionAsm(void) { return ud_insn_asm(&m_udis_obj); }
    const ud_operand_t* InstructionOperand(const unsigned __int32 n) { return ud_insn_opr(&m_udis_obj, n); }
    enum ud_mnemonic_code InstructionMnemonic(void) { return ud_insn_mnemonic(&m_udis_obj); }

    void SetInputBuffer(const unsigned char* buffer, const size_t size);

 private:
    void Init(const unsigned __int8 mode);

    bool                             m_inited;
    std::unique_ptr<unsigned char[]> m_buffer;
    size_t                           m_size;
    ud_t                             m_udis_obj;
    //////////////////////////////////////////////////////////////////////////
    // output streams
    //////////////////////////////////////////////////////////////////////////
    std::stringstream out;
    std::stringstream warn;
    std::stringstream err;
};

}   // namespace wa

#endif  // UDIS_HPP_
