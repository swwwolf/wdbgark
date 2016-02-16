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

/*
// This routine maps g_CiOptions into SYSTEM_CODEINTEGRITY_INFORMATION
// Also look https://msdn.microsoft.com/ru-ru/library/windows/desktop/ms724509(v=vs.85).aspx
// Windows 10.10240
NTSTATUS __fastcall CiQueryInformation(SYSTEM_CODEINTEGRITY_INFORMATION *pBuffer,
                                       __int64 BufSize,
                                       __int64 bSeILSigningPolicyNotUnchecked,
                                       _DWORD *ReturnLength)
{
  char locbSeILSigningPolicyNotUnchecked; // si@1
  SYSTEM_CODEINTEGRITY_INFORMATION *locpBuffer; // rbx@1
  NTSTATUS status; // edi@1
  char g_CiOptions_low_byte; // cl@7
  int v8; // ecx@24
  int v9; // eax@24
  char v11; // [sp+48h] [bp+10h]@5
  char v12; // [sp+58h] [bp+20h]@5
  int v13; // [sp+5Ch] [bp+24h]@6

  locbSeILSigningPolicyNotUnchecked = bSeILSigningPolicyNotUnchecked;
  locpBuffer = pBuffer;                         // SYSTEM_CODEINTEGRITY_INFORMATION
  status = 0;
  *ReturnLength = 8;
  if ( (unsigned int)BufSize >= 8 )
  {
    if ( pBuffer->Length != 8 || (_DWORD)BufSize != 8 )
    {
      status = STATUS_INFO_LENGTH_MISMATCH;
    }
    else
    {
      pBuffer->CodeIntegrityOptions = 0;

      // Get CI options from XBOX :)
      if ( XciQueryInformation_0((__int64)&v12, BufSize, bSeILSigningPolicyNotUnchecked, (__int64)&v11) >= 0 )
        locpBuffer->CodeIntegrityOptions |= v13;
      g_CiOptions_low_byte = g_CiOptions;
      if ( g_CiOptions & 2 && (!*KdDebuggerEnabled || *KdDebuggerNotPresent || g_CiOptions & 0x10) )
      {
        locpBuffer->CodeIntegrityOptions |= 1u; // CODEINTEGRITY_OPTION_ENABLED
        g_CiOptions_low_byte = g_CiOptions;
      }
      if ( g_CiOptions_low_byte & 8 )
        locpBuffer->CodeIntegrityOptions |= 2u; // CODEINTEGRITY_OPTION_TESTSIGN
      if ( *KdDebuggerEnabled && *KdDebuggerNotPresent != 1 )
        locpBuffer->CodeIntegrityOptions |= 0x80u;// CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED
      if ( locbSeILSigningPolicyNotUnchecked )
      {
        locpBuffer->CodeIntegrityOptions |= 4u; // CODEINTEGRITY_OPTION_UMCI_ENABLED
        if ( g_CiDeveloperMode & 1 )
          locpBuffer->CodeIntegrityOptions |= 8u;// CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED
        if ( g_CiDeveloperMode & 2 )
          locpBuffer->CodeIntegrityOptions |= 0x10u;// CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED
      }
      if ( g_CiDeveloperMode & 0x100 )
        locpBuffer->CodeIntegrityOptions |= 0x200u;// CODEINTEGRITY_OPTION_FLIGHTING_ENABLED
      v8 = locpBuffer->CodeIntegrityOptions;
      locpBuffer->CodeIntegrityOptions = v8;
      v9 = g_CiOptions;
      if ( _bittest(&v9, 0xEu) )
      {
        locpBuffer->CodeIntegrityOptions = v8 | 0x2000;// CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED
        v9 = g_CiOptions;
      }
      if ( _bittest(&v9, 0xFu) )
      {
        locpBuffer->CodeIntegrityOptions |= 0x400u;// CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
        v9 = g_CiOptions;
      }
      if ( _bittest(&v9, 0x10u) )
        locpBuffer->CodeIntegrityOptions |= 0x1000u;// CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED
      if ( g_CiDeveloperMode & 0x200 )
        locpBuffer->CodeIntegrityOptions |= 0x800u;// CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED
    }
  }
  else
  {
    status = STATUS_INFO_LENGTH_MISMATCH;
  }
  return status;
}
*/

#include <sstream>
#include <memory>
#include <string>
#include <utility>

#include "wdbgark.hpp"
#include "manipulators.hpp"
#include "strings.hpp"
#include "./ddk.h"

namespace wa {

std::string CiQueryInformation(const uint32_t ci_options,
                               const uint32_t ci_dev_mode,
                               const bool seil_sign_flag,
                               const bool dbg_enabled,
                               const bool dbg_not_present);

EXT_COMMAND(wa_ciinfo, "Output Code Integrity information", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Displaying Code Integrity information" << endlout;

    if ( m_system_ver->GetStrictVer() <= VISTA_SP1_VER ) {
        out << wa::showplus << __FUNCTION__ << ": unsupported Windows version" << endlout;
        return;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache);

    try {
        std::string g_ci_options = "ci!g_CiOptions";
        uint64_t g_ci_options_offset = 0;

        if ( !m_sym_cache->GetSymbolOffset(g_ci_options, true, &g_ci_options_offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find " << g_ci_options << endlerr;
            return;
        }

        ExtRemoteData g_ci_options_data(g_ci_options_offset, sizeof(uint32_t));

        std::string kddebuggerenabled = "nt!KdDebuggerEnabled";
        uint64_t kddebuggerenabled_offset = 0;

        if ( !m_sym_cache->GetSymbolOffset(kddebuggerenabled, true, &kddebuggerenabled_offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find " << kddebuggerenabled << endlerr;
            return;
        }

        ExtRemoteData kddebuggerenabled_data(kddebuggerenabled_offset, sizeof(uint8_t));

        std::string kddebuggernotpresent = "nt!KdDebuggerNotPresent";
        uint64_t kddebuggernotpresent_offset = 0;

        if ( !m_sym_cache->GetSymbolOffset(kddebuggernotpresent, true, &kddebuggernotpresent_offset) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to find " << kddebuggernotpresent << endlerr;
            return;
        }

        ExtRemoteData kddebuggernotpresent_data(kddebuggernotpresent_offset, sizeof(uint8_t));

        out << wa::showplus << g_ci_options << "      : " << std::hex << std::showbase << g_ci_options_data.GetUlong();
        out << endlout;

        std::string g_cidevelopermode = "ci!g_CiDeveloperMode";
        uint64_t g_cidevelopermode_offset = 0;
        ExtRemoteData g_cidevelopermode_data;

        if ( m_sym_cache->GetSymbolOffset(g_cidevelopermode, true, &g_cidevelopermode_offset) ) {
            g_cidevelopermode_data.Set(g_cidevelopermode_offset, sizeof(uint32_t));

            out << wa::showplus << g_cidevelopermode << ": " << std::hex << std::showbase;
            out << g_cidevelopermode_data.GetUlong() << endlout;
        }

        std::string seilsigningpolicy = "nt!SeILSigningPolicy";
        uint64_t seilsigningpolicy_offset = 0;
        ExtRemoteData seilsigningpolicy_data;

        if ( m_sym_cache->GetSymbolOffset(seilsigningpolicy, true, &seilsigningpolicy_offset) ) {
            seilsigningpolicy_data.Set(seilsigningpolicy_offset, sizeof(uint8_t));

            out << wa::showplus << seilsigningpolicy << ": ";
            out << std::internal << std::setw(2) << std::setfill('0') << std::hex << std::showbase;
            out << static_cast<int>(seilsigningpolicy_data.GetUchar()) << endlout;
        }

        out << wa::showplus << "Mapped options      : \n" << CiQueryInformation(
            g_ci_options_data.GetUlong(),
            g_cidevelopermode_offset ? g_cidevelopermode_data.GetUlong() : 0ULL,
            seilsigningpolicy_offset ? (seilsigningpolicy_data.GetUchar() != 0) : false,
            kddebuggerenabled_data.GetStdBool(),
            kddebuggernotpresent_data.GetStdBool());

        out << endlout;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
    display->PrintFooter();
}

std::string CiQueryInformation(const uint32_t ci_options,
                               const uint32_t ci_dev_mode,
                               const bool seil_sign_flag,
                               const bool dbg_enabled,
                               const bool dbg_not_present) {
    std::stringstream mapped_options;

    if ( (ci_options & 2) && (!dbg_enabled || dbg_not_present || ci_options & 0x10) ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_ENABLED) << " |\n";
    }

    if ( ci_options & 8 ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_TESTSIGN) << " |\n";
    }

    if ( dbg_enabled && dbg_not_present != true ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) << " |\n";
    }

    if ( seil_sign_flag ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_UMCI_ENABLED) << " |\n";

        if ( ci_dev_mode & 1 ) {
            mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
            mapped_options << make_string(CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED) << " |\n";
        }

        if ( ci_dev_mode & 2 ) {
            mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
            mapped_options << make_string(CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED) << " |\n";
        }
    }

    if ( ci_dev_mode & 0x100 ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_FLIGHTING_ENABLED) << " |\n";
    }

    if ( _bittest(reinterpret_cast<const long*>(&ci_options), 0xEu) ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) << " |\n";
    }

    if ( _bittest(reinterpret_cast<const long*>(&ci_options), 0xFu) ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) << " |\n";
    }

    if ( _bittest(reinterpret_cast<const long*>(&ci_options), 0x10u) ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED) << " |\n";
    }

    if ( ci_dev_mode & 0x200 ) {
        mapped_options << std::right << std::setfill(' ') << std::setw(26) << " ";
        mapped_options << make_string(CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED) << " |\n";
    }

    std::string options = mapped_options.str();

    if ( !options.empty() ) {
        if ( options.substr(options.length() - 3, 3) == " |\n" )
            options.erase(options.length() - 3);
    }

    return options;
}

}   // namespace wa
