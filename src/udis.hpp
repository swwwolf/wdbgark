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
    WDbgArkUdis(uint8_t mode, uint64_t address, size_t size);   // mode = 32/64, 0 - default

    bool IsInited(void) const { return m_inited; }
    const ud_t Get(void) const { return m_udis_obj; }
    void SwitchMode(const uint8_t mode) { ud_set_mode(&m_udis_obj, mode); }
    void SetInstructionPointer(const uint64_t ip) { ud_set_pc(&m_udis_obj, ip); }
    uint32_t Disassemble(void) { return ud_disassemble(&m_udis_obj); }
    uint32_t InstructionLength(void) { return ud_insn_len(&m_udis_obj); }
    uint64_t InstructionOffset(void) { return ud_insn_off(&m_udis_obj); }
    const char* InstructionHex(void) { return ud_insn_hex(&m_udis_obj); }
    const uint8_t* InstructionPointer(void) { return ud_insn_ptr(&m_udis_obj); }
    const char* InstructionAsm(void) { return ud_insn_asm(&m_udis_obj); }
    const ud_operand_t* InstructionOperand(const uint32_t n) { return ud_insn_opr(&m_udis_obj, n); }
    enum ud_mnemonic_code InstructionMnemonic(void) { return ud_insn_mnemonic(&m_udis_obj); }

    bool SetInputBuffer(const uint8_t* buffer, const size_t size);
    bool SetInputBuffer(const uint64_t address, const size_t size);

 private:
    void Init(const uint8_t mode);

 private:
    bool m_inited = false;
    std::unique_ptr<uint8_t[]> m_buffer{ nullptr };
    size_t m_size = 0;
    ud_t m_udis_obj = { 0 };
};

}   // namespace wa

#endif  // UDIS_HPP_
