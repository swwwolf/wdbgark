/*
    * WinDBG Anti-RootKit extension
    * Copyright © 2013-2014  Vyacheslav Rusakoff
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

// IDT entry

struct _KIDTENTRY {

    unsigned short Offset;
    unsigned short Selector;
    unsigned short Access;
    unsigned short ExtendedOffset;
};
// <size 0x08>

union _KIDTENTRY64 {

    unsigned short OffsetLow;
    unsigned short Selector;
    unsigned short IstIndex:0:3;
    unsigned short Reserved0:3:5;
    unsigned short Type:8:5;
    unsigned short Dpl:d:2;
    unsigned short Present:f:1;
    unsigned short OffsetMiddle;
    unsigned long OffsetHigh;
    unsigned long Reserved1;
    unsigned __int64 Alignment;
};
// <size 0x10>

// GDT entry

typedef struct _KGDTENTRY {
    USHORT  LimitLow;
    USHORT  BaseLow;
    union {
        struct {
            UCHAR   BaseMid;
            UCHAR   Flags1;     // Declare as bytes to avoid alignment
            UCHAR   Flags2;     // Problems.
            UCHAR   BaseHi;
        } Bytes;
        struct {
            ULONG   BaseMid : 8;
            ULONG   Type : 5;
            ULONG   Dpl : 2;
            ULONG   Pres : 1;
            ULONG   LimitHi : 4;
            ULONG   Sys : 1;
            ULONG   Reserved_0 : 1;
            ULONG   Default_Big : 1;
            ULONG   Granularity : 1;
            ULONG   BaseHi : 8;
        } Bits;
    } HighWord;
} KGDTENTRY, *PKGDTENTRY;
// <size 0x8>

typedef union _KGDTENTRY64 {
    struct {
        USHORT  LimitLow;
        USHORT  BaseLow;
        union {
            struct {
                UCHAR   BaseMiddle;
                UCHAR   Flags1;
                UCHAR   Flags2;
                UCHAR   BaseHigh;
            } Bytes;

            struct {
                ULONG   BaseMiddle : 8;
                ULONG   Type : 5;
                ULONG   Dpl : 2;
                ULONG   Present : 1;
                ULONG   LimitHigh : 4;
                ULONG   System : 1;
                ULONG   LongMode : 1;
                ULONG   DefaultBig : 1;
                ULONG   Granularity : 1;
                ULONG   BaseHigh : 8;
            } Bits;
        };

        ULONG BaseUpper;
        ULONG MustBeZero;
    };

    ULONG64 Alignment;
} KGDTENTRY64, *PKGDTENTRY64;
// <size 0x10>

*/

#include "wdbgark.h"

EXT_COMMAND(idt,
            "Output processors IDTs\n",
            "")
{
    RequireKernelMode();

    Init();

    out << "******" << endlout;
    out << "*    ";
    out << std::left << std::setw( 16 ) << "Address" << std::right << std::setw( 6 ) << ' ';
    out << std::left << std::setw( 40 ) << "Processor(core)/Index" << std::right << std::setw( 12 ) << ' ';
    out << std::left << std::setw( 70 ) << "Symbol" << std::right << std::setw( 4 ) << ' ';
    out << std::left << std::setw( 30 ) << "Module" << std::right << std::setw( 1 ) << ' ';
    out << "*" << endlout;
    out << "******" << endlout;

    try
    {
        for ( unsigned int i = 0; i < g_Ext->m_NumProcessors; i++ )
        {
            unsigned __int64 kpcr_offset     = 0;
            unsigned __int64 idt_entry_start = 0;
            unsigned long    idt_entry_size  = 0;

            g_Ext->m_Data->ReadProcessorSystemData(i,
                                                   DEBUG_DATA_KPCR_OFFSET,
                                                   &kpcr_offset,
                                                   sizeof( kpcr_offset ),
                                                   NULL);

            ExtRemoteTyped pcr( "nt!_KPCR", kpcr_offset, false, NULL, NULL );

            if ( is_cur_machine64 )
            {
                idt_entry_start = pcr.Field( "IdtBase" ).GetPtr(); // _KIDTENTRY64*
                idt_entry_size = GetTypeSize( "nt!_KIDTENTRY64" );
            }
            else
            {
                idt_entry_start = pcr.Field( "IDT" ).GetPtr(); // _KIDTENTRY*
                idt_entry_size = GetTypeSize( "nt!_KIDTENTRY" );
            }

            for ( unsigned long j = 0; j < 0x100; j++ )
            {
                unsigned __int64 isr_address = 0;

                stringstream processor_index;
                processor_index << i << " / " << j;

                if ( is_cur_machine64 )
                {
                    KIDT_HANDLER_ADDRESS idt_handler = { 0 };

                    ExtRemoteTyped idt_entry("nt!_KIDTENTRY64",
                                             idt_entry_start + j * idt_entry_size,
                                             false,
                                             NULL,
                                             NULL);

                    idt_handler.OffsetLow = idt_entry.Field( "OffsetLow" ).GetUshort();
                    idt_handler.OffsetMiddle = idt_entry.Field( "OffsetMiddle" ).GetUshort();
                    idt_handler.OffsetHigh = idt_entry.Field( "OffsetHigh" ).GetUlong();

                    isr_address = idt_handler.Address;
                }
                else
                {
                    ExtRemoteTyped idt_entry("nt!_KIDTENTRY",
                                             idt_entry_start + j * idt_entry_size,
                                             false,
                                             NULL,
                                             NULL);

                    isr_address = (unsigned __int64 )MAKEULONG(idt_entry.Field( "ExtendedOffset" ).GetUshort(),
                                                               idt_entry.Field( "Offset" ).GetUshort());

                    stringstream expression;
                    expression << std::showbase << std::hex << isr_address;
                    
                    isr_address = g_Ext->EvalExprU64( expression.str().c_str() );
                }

                AnalyzeAddressAsRoutine( isr_address, processor_index.str(), "" );
            }           
        }
    }
    catch( ... )
    {
        err << "Exception in " << __FUNCTION__ << endlerr;
    }

    out << "******" << endlout;
}