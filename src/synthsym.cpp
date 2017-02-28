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

#include <string>

#include "wdbgark.hpp"
#include "udis.hpp"
#include "util.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
void WDbgArk::RemoveSyntheticSymbols() {
    if ( !m_symbols3_iface.IsSet() )
        return;

    for ( auto &id : m_synthetic_symbols ) {
        m_symbols3_iface->RemoveSyntheticSymbol(&id);
    }
}
//////////////////////////////////////////////////////////////////////////
bool WDbgArk::AddSyntheticSymbolAddressPtr(const uint64_t address, const std::string &name) {
    uint64_t result_address = 0;

    if ( !NormalizeAddress(address, &result_address) )
        return false;

    // do not reload nt module after
    DEBUG_MODULE_AND_ID id;
    HRESULT result = m_Symbols3->AddSyntheticSymbol(result_address,
                                                    m_PtrSize,
                                                    name.c_str(),
                                                    DEBUG_ADDSYNTHSYM_DEFAULT,
                                                    &id);

    if ( !SUCCEEDED(result) ) {
        err << wa::showminus << __FUNCTION__ << ": failed to add synthetic symbol " << name << endlerr;
    } else {
        m_synthetic_symbols.push_back(id);
        return true;
    }

    return false;
}
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// DbgkLkmdCallbackArray
//////////////////////////////////////////////////////////////////////////
/*
x86:

PAGE:006A4FCB                               ; __stdcall DbgkLkmdUnregisterCallback(x)
PAGE:006A4FCB                                               public _DbgkLkmdUnregisterCallback@4
PAGE:006A4FCB                               _DbgkLkmdUnregisterCallback@4 proc near
PAGE:006A4FCB
PAGE:006A4FCB                               arg_0           = dword ptr  8
PAGE:006A4FCB
PAGE:006A4FCB 8B FF                                         mov     edi, edi
PAGE:006A4FCD 55                                            push    ebp
PAGE:006A4FCE 8B EC                                         mov     ebp, esp
PAGE:006A4FD0 53                                            push    ebx
PAGE:006A4FD1 56                                            push    esi
PAGE:006A4FD2 57                                            push    edi
PAGE:006A4FD3 33 DB                                         xor     ebx, ebx
PAGE:006A4FD5 BF 20 5B 52 00                                mov     edi, offset dword_525B20 <-- !!!
PAGE:006A4FDA
PAGE:006A4FDA                               loc_6A4FDA:
PAGE:006A4FDA 57                                            push    edi
PAGE:006A4FDB E8 52 1C FC FF                                call    _ExReferenceCallBackBlock@4

x64:

PAGE:0000000140482150                               DbgkLkmdUnregisterCallback proc near
PAGE:0000000140482150
PAGE:0000000140482150                               arg_0           = qword ptr  8
PAGE:0000000140482150                               arg_8           = qword ptr  10h
PAGE:0000000140482150                               arg_10          = qword ptr  18h
PAGE:0000000140482150
PAGE:0000000140482150 48 89 5C 24 08                                mov     [rsp+arg_0], rbx
PAGE:0000000140482155 48 89 6C 24 10                                mov     [rsp+arg_8], rbp
PAGE:000000014048215A 48 89 74 24 18                                mov     [rsp+arg_10], rsi
PAGE:000000014048215F 57                                            push    rdi
PAGE:0000000140482160 41 54                                         push    r12
PAGE:0000000140482162 41 55                                         push    r13
PAGE:0000000140482164 48 83 EC 20                                   sub     rsp, 20h
PAGE:0000000140482168 33 FF                                         xor     edi, edi
PAGE:000000014048216A 48 8B E9                                      mov     rbp, rcx
PAGE:000000014048216D 4C 8D 2D 9C 1E D7 FF                          lea     r13, unk_1401F4010 <-- !!!
PAGE:0000000140482174 44 8D 67 01                                   lea     r12d, [rdi+1]
PAGE:0000000140482178
PAGE:0000000140482178                               loc_140482178:
PAGE:0000000140482178 8B F7                                         mov     esi, edi
PAGE:000000014048217A 48 C1 E6 04                                   shl     rsi, 4
PAGE:000000014048217E 49 03 F5                                      add     rsi, r13
PAGE:0000000140482181 48 8B CE                                      mov     rcx, rsi
PAGE:0000000140482184 E8 37 B1 F0 FF                                call    ExReferenceCallBackBlock
*/

bool WDbgArk::FindDbgkLkmdCallbackArray() {
    if ( m_system_ver->GetStrictVer() <= VISTA_SP2_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return false;
    }

    uint64_t symbol_offset = 0;

    if ( m_sym_cache->GetSymbolOffset("nt!DbgkLkmdCallbackArray", true, &symbol_offset) )
        return true;

    uint64_t offset = 0;

    if ( !m_sym_cache->GetSymbolOffset("nt!DbgkLkmdUnregisterCallback", true, &offset) ) {
        err << wa::showminus << __FUNCTION__ << ": can't find nt!DbgkLkmdUnregisterCallback" << endlerr;
        return false;
    }

    WDbgArkUdis udis(0, offset, MAX_INSN_LENGTH * 20);

    if ( !udis.IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": can't init UDIS class" << endlerr;
        return false;
    }

    uint64_t address = 0;

    while ( udis.Disassemble() ) {
        if ( !m_is_cur_machine64 && udis.InstructionLength() == 5 && udis.InstructionMnemonic() == UD_Imov &&
             udis.InstructionOperand(0)->type == UD_OP_REG ) {
            address = static_cast<uint64_t>(udis.InstructionOperand(1)->lval.udword);
            break;
        } else if ( m_is_cur_machine64 && udis.InstructionLength() == 7 && udis.InstructionMnemonic() == UD_Ilea &&
                    udis.InstructionOperand(0)->type == UD_OP_REG ) {
            address = udis.InstructionOffset() + udis.InstructionOperand(1)->lval.sdword + udis.InstructionLength();
            break;
        }
    }

    if ( !address ) {
        err << wa::showminus << __FUNCTION__ << ": disassembly failed" << endlerr;
        return false;
    }

    return AddSyntheticSymbolAddressPtr(address, "DbgkLkmdCallbackArray");
}
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// MiApiSetSchema
//////////////////////////////////////////////////////////////////////////
/*
x86:

PAGE:007114C6                               ; int __thiscall MiResolveImageReferences(PVOID ImageBase, int, int, int)
PAGE:007114C6 8B FF                                         mov     edi, edi
PAGE:007114C8 53                                            push    ebx
PAGE:007114C9 8B DC                                         mov     ebx, esp
PAGE:007114CB 51                                            push    ecx
PAGE:007114CC 51                                            push    ecx
PAGE:007114CD 83 E4 F8                                      and     esp, 0FFFFFFF8h
...
PAGE:00711597 E8 44 F2 FB FF                                call    _RtlAnsiStringToUnicodeString@12
PAGE:0071159C 8B F0                                         mov     esi, eax
PAGE:0071159E 85 F6                                         test    esi, esi
PAGE:007115A0 0F 88 1A F4 0D 00                             js      loc_7F09C0
PAGE:007115A6 83 7D B4 00                                   cmp     dword ptr [ebp-4Ch], 0
PAGE:007115AA 0F 84 0B F4 0D 00                             jz      loc_7F09BB
PAGE:007115B0 8B 0D B0 DA 60 00                             mov     ecx, dword_60DAB0           <-- !!!
PAGE:007115B6 8D 45 A0                                      lea     eax, [ebp-60h]
PAGE:007115B9 50                                            push    eax
PAGE:007115BA 8D 45 FF                                      lea     eax, [ebp-1]
PAGE:007115BD 50                                            push    eax
PAGE:007115BE FF 75 C4                                      push    dword ptr [ebp-3Ch]
PAGE:007115C1 8D 55 B0                                      lea     edx, [ebp-50h]
PAGE:007115C4 E8 09 27 D3 FF                                call    _ApiSetResolveToHost@20     <-- !!!
PAGE:007115C9 8B F0                                         mov     esi, eax
PAGE:007115CB 85 F6                                         test    esi, esi
...

Windows 10 RS1 x86:
.text:0045CFE8                               ; __stdcall MmQueryApiSetSchema(x, x)
.text:0045CFE8                               _MmQueryApiSetSchema@8 proc near
.text:0045CFE8 C7 01 F0 12 61 00                             mov     dword ptr [ecx], offset dword_6112F0   <-- !!!
.text:0045CFEE C7 02 F4 12 61 00                             mov     dword ptr [edx], offset dword_6112F4
.text:0045CFF4 C3                                            retn
.text:0045CFF4                               _MmQueryApiSetSchema@8 endp

x64:

PAGE:000000014042BAC8                               MiResolveImageReferences proc near
PAGE:000000014042BAC8 48 8B C4                                      mov     rax, rsp
PAGE:000000014042BACB 4C 89 48 20                                   mov     [rax+20h], r9
PAGE:000000014042BACF 4C 89 40 18                                   mov     [rax+18h], r8
PAGE:000000014042BAD3 48 89 50 10                                   mov     [rax+10h], rdx
PAGE:000000014042BAD7 48 89 48 08                                   mov     [rax+8], rcx
PAGE:000000014042BADB 55                                            push    rbp
PAGE:000000014042BADC 53                                            push    rbx
PAGE:000000014042BADD 56                                            push    rsi
PAGE:000000014042BADE 57                                            push    rdi
PAGE:000000014042BADF 41 54                                         push    r12
PAGE:000000014042BAE1 41 55                                         push    r13
PAGE:000000014042BAE3 41 56                                         push    r14
PAGE:000000014042BAE5 41 57                                         push    r15
...
PAGE:000000014042BBDA E8 85 6E 0A 00                                call    RtlAnsiStringToUnicodeString
PAGE:000000014042BBDF 8B F8                                         mov     edi, eax
PAGE:000000014042BBE1 33 C0                                         xor     eax, eax
PAGE:000000014042BBE3 85 FF                                         test    edi, edi
PAGE:000000014042BBE5 0F 88 AA 2A 15 00                             js      loc_14057E695
PAGE:000000014042BBEB 48 39 45 97                                   cmp     [rbp-69h], rax
PAGE:000000014042BBEF 0F 84 9B 2A 15 00                             jz      loc_14057E690
PAGE:000000014042BBF5 4C 8B 45 67                                   mov     r8, [rbp+67h]
PAGE:000000014042BBF9 48 8D 45 BF                                   lea     rax, [rbp-41h]
PAGE:000000014042BBFD 48 8B 0D 5C F7 EC FF                          mov     rcx, cs:qword_1402FB360     <-- !!!
PAGE:000000014042BC04 4C 8D 4C 24 34                                lea     r9, [rsp+118h+var_E4]
PAGE:000000014042BC09 48 8D 55 8F                                   lea     rdx, [rbp-71h]
PAGE:000000014042BC0D 48 89 44 24 20                                mov     [rsp+118h+var_F8], rax
PAGE:000000014042BC12 E8 79 5C CB FF                                call    ApiSetResolveToHost         <-- !!!
PAGE:000000014042BC17 8B F8                                         mov     edi, eax
PAGE:000000014042BC19 33 C0                                         xor     eax, eax
PAGE:000000014042BC1B 85 FF                                         test    edi, edi
...

Windows 10 RS1 x64:
.text:0000000140113A00                               MmQueryApiSetSchema proc near
.text:0000000140113A00 48 8D 05 A1 E8 1E 00                          lea     rax, qword_1403022A8       <-- !!!
.text:0000000140113A07 48 89 01                                      mov     [rcx], rax
.text:0000000140113A0A 48 8D 05 9F E8 1E 00                          lea     rax, qword_1403022B0
.text:0000000140113A11 48 89 02                                      mov     [rdx], rax
.text:0000000140113A14 C3                                            retn
.text:0000000140113A14                               MmQueryApiSetSchema endp
*/
bool WDbgArk::FindMiApiSetSchema() {
    if ( m_system_ver->GetStrictVer() <= W81RTM_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return false;
    }

    uint64_t symbol_offset = 0;

    if ( m_sym_cache->GetSymbolOffset("nt!MiApiSetSchema", true, &symbol_offset) )
        return true;

    uint64_t offset = 0;
    size_t disasm_len = m_PageSize;

    if ( m_system_ver->GetStrictVer() <= W10TH2_VER ) {
        if ( !m_sym_cache->GetSymbolOffset("nt!MiResolveImageReferences", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": can't find nt!MiResolveImageReferences" << endlerr;
            return false;
        }
    } else {
        if ( !m_sym_cache->GetSymbolOffset("nt!MmQueryApiSetSchema", true, &offset) ) {
            err << wa::showminus << __FUNCTION__ << ": can't find nt!MmQueryApiSetSchema" << endlerr;
            return false;
        }

        disasm_len = 4 * MAX_INSN_LENGTH;
    }

    WDbgArkUdis udis(0, offset, disasm_len);

    if ( !udis.IsInited() ) {
        err << wa::showminus << __FUNCTION__ << ": can't init UDIS class" << endlerr;
        return false;
    }

    uint64_t address = 0;

    while ( udis.Disassemble() ) {
        if ( m_system_ver->GetStrictVer() <= W10TH2_VER ) {
            uint64_t check_address = 0;

            if ( !m_is_cur_machine64 &&
                 udis.InstructionLength() == 6 && udis.InstructionMnemonic() == UD_Imov &&
                 udis.InstructionOperand(0)->type == UD_OP_REG && udis.InstructionOperand(1)->type == UD_OP_MEM ) {
                check_address = udis.InstructionOffset() + udis.InstructionLength();
            } else if ( m_is_cur_machine64 &&
                        udis.InstructionLength() == 7 && udis.InstructionMnemonic() == UD_Imov &&
                        udis.InstructionOperand(0)->type == UD_OP_REG &&
                        udis.InstructionOperand(1)->type == UD_OP_MEM ) {
                check_address = udis.InstructionOffset() + udis.InstructionLength();
            }

            if ( check_address ) {
                WDbgArkUdis udis_local(0, check_address, 10 * MAX_INSN_LENGTH);

                if ( !udis_local.IsInited() )
                    continue;

                while ( udis_local.Disassemble() ) {
                    if ( udis_local.InstructionLength() == 5 && udis_local.InstructionMnemonic() == UD_Icall ) {
                        uint64_t call_address = udis_local.InstructionOffset() + \
                            udis_local.InstructionOperand(0)->lval.sdword + udis_local.InstructionLength();

                        auto result = m_symbols_base->GetNameByOffset(call_address);

                        if ( SUCCEEDED(result.first) && result.second == "nt!ApiSetResolveToHost" ) {
                            if ( !m_is_cur_machine64 ) {
                                address = static_cast<uint64_t>(udis.InstructionOperand(1)->lval.udword);
                            } else {
                                address = udis.InstructionOffset() + udis.InstructionOperand(1)->lval.sdword + \
                                    udis.InstructionLength();
                            }
                            break;  // break from inner loop
                        }
                    }
                }

                if ( address )  // global break
                    break;
            }
        } else {
            if ( !m_is_cur_machine64 &&
                 udis.InstructionLength() == 6 && udis.InstructionMnemonic() == UD_Imov &&
                 udis.InstructionOperand(0)->type == UD_OP_MEM && udis.InstructionOperand(1)->type == UD_OP_IMM ) {
                address = static_cast<uint64_t>(udis.InstructionOperand(1)->lval.udword);
                break;
            } else if ( m_is_cur_machine64 &&
                        udis.InstructionLength() == 7 && udis.InstructionMnemonic() == UD_Ilea &&
                        udis.InstructionOperand(0)->type == UD_OP_REG &&
                        udis.InstructionOperand(1)->type == UD_OP_MEM ) {
                address = udis.InstructionOffset() + udis.InstructionOperand(1)->lval.sdword + udis.InstructionLength();
                break;
            }
        }
    }

    if ( !address ) {
        err << wa::showminus << __FUNCTION__ << ": disassembly failed" << endlerr;
        return false;
    }

    return AddSyntheticSymbolAddressPtr(address, "MiApiSetSchema");
}
//////////////////////////////////////////////////////////////////////////
}   // namespace wa
