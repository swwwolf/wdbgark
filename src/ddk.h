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

#ifndef SRC_DDK_H_
#define SRC_DDK_H_

namespace wa {

//////////////////////////////////////////////////////////////////////////
// macroses
//////////////////////////////////////////////////////////////////////////
#define MAKEULONG(x, y) ( ((((unsigned __int32)(x)) << 16) & 0xFFFF0000) | ((unsigned __int32)(y) & 0xFFFF) )
#define CHECK_BIT_SET(x, y) (x & (1 << y))

#define PAGE_SIZE  0x1000
#define PAGE_SHIFT 12L
//////////////////////////////////////////////////////////////////////////
// Windows builds
//////////////////////////////////////////////////////////////////////////
#define WXP_VER         2600    // Windows XP
#define W2K3_VER        3790    // Windows 2003
#define VISTA_RTM_VER   6000    // Windows Vista SP0
#define VISTA_SP1_VER   6001    // Windows Vista SP1 / Windows Server 2008 SP1
#define VISTA_SP2_VER   6002    // Windows Vista SP2 / Windows Server 2008 SP2
#define W7RTM_VER       7600    // Windows 7 SP0
#define W7SP1_VER       7601    // Windows 7 SP1
#define W8RTM_VER       9200    // Windows 8 SP0
#define W81RTM_VER      9600    // Windows 8.1 RTM
#define W10RTM_VER      10240   // Windows 10 RTM

//////////////////////////////////////////////////////////////////////////
// drivers
//////////////////////////////////////////////////////////////////////////
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

//////////////////////////////////////////////////////////////////////////
// objects
//////////////////////////////////////////////////////////////////////////
enum OBJ_HEADER_INFO_FLAG {
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag    = 0x2,
    HeaderHandleInfoFlag  = 0x4,
    HeaderQuotaInfoFlag   = 0x8,
    HeaderProcessInfoFlag = 0x10
};

#define NOTIFY_DEVICE_CLASS_HASH_BUCKETS  13
#define MAX_FAST_REFS_X64                 15
#define MAX_FAST_REFS_X86                 7
#define OBJTYPE_SUPPORTS_OBJECT_CALLBACKS (1 << 6)

//////////////////////////////////////////////////////////////////////////
// MSRs
//////////////////////////////////////////////////////////////////////////
#define IA32_SYSENTER_EIP                0x176
#define MSR_LSTAR                        0xC0000082  // system call 64-bit entry
#define MSR_CSTAR                        0xC0000083  // system call 32-bit entry

//////////////////////////////////////////////////////////////////////////
// kernel object types
//////////////////////////////////////////////////////////////////////////
typedef enum _KOBJECTS {
    EventNotificationObject = 0,
    EventSynchronizationObject = 1,
    MutantObject = 2,
    ProcessObject = 3,
    QueueObject = 4,
    SemaphoreObject = 5,
    ThreadObject = 6,
    GateObject = 7,
    TimerNotificationObject = 8,
    TimerSynchronizationObject = 9,
    Spare2Object = 10,
    Spare3Object = 11,
    Spare4Object = 12,
    Spare5Object = 13,
    Spare6Object = 14,
    Spare7Object = 15,
    Spare8Object = 16,
    Spare9Object = 17,
    ApcObject = 18,
    DpcObject = 19,
    DeviceQueueObject = 20,
    EventPairObject = 21,
    InterruptObject = 22,
    ProfileObject = 23,
    ThreadedDpcObject = 24,
    MaximumKernelObject = 25
} KOBJECTS;

//////////////////////////////////////////////////////////////////////////
// IDT/GDT
//////////////////////////////////////////////////////////////////////////
typedef union _KIDT_HANDLER_ADDRESS {
    struct {
        unsigned __int16 OffsetLow;
        unsigned __int16 OffsetMiddle;
        unsigned __int32 OffsetHigh;
    } off;

    unsigned __int64   Address;
} KIDT_HANDLER_ADDRESS, *PKIDT_HANDLER_ADDRESS;

#define PRIMARY_VECTOR_BASE              0x30
#define MAXIMUM_IDTVECTOR                0xFF

// selectors x86
#define KGDT_R0_CODE                     0x8
#define KGDT_R0_DATA                     0x10
#define KGDT_R3_CODE                     0x18
#define KGDT_R3_DATA                     0x20
#define KGDT_TSS                         0x28   // nt!_KTSS
#define KGDT_R0_PCR                      0x30   // nt!_KPCR
#define KGDT_R3_TEB                      0x38
#define KGDT_LDT                         0x48
#define KGDT_DF_TSS                      0x50   // nt!_KTSS
#define KGDT_NMI_TSS                     0x58   // nt!_KTSS
#define KGDT_GDT_ALIAS                   0x70
#define KGDT_CDA16                       0xE8
#define KGDT_CODE16                      0xF0
#define KGDT_STACK16                     0xF8

// selectors x64
#define KGDT64_NULL                      0x00
#define KGDT64_R0_CODE                   0x10
#define KGDT64_R0_DATA                   0x18
#define KGDT64_R3_CMCODE                 0x20
#define KGDT64_R3_DATA                   0x28
#define KGDT64_R3_CODE                   0x30
#define KGDT64_SYS_TSS                   0x40   // nt!_KTSS64
#define KGDT64_R3_CMTEB                  0x50

// http://wiki.osdev.org/Global_Descriptor_Table
// http://wiki.osdev.org/GDT_Tutorial
// Each define here is for a specific flag in the descriptor.
// Refer to the intel documentation for a description of what each one does.
// Intel manual 3.4.5.1
#define SEG_DESCTYPE(x)                  ((x) << 0x04)              // Descriptor type (0 for system, 1 for code/data)
#define SEG_PRES(x)                      ((x) << 0x07)              // Present
#define SEG_SAVL(x)                      ((x) << 0x0C)              // Available for system use
#define SEG_LONG(x)                      ((x) << 0x0D)              // Long mode
#define SEG_SIZE(x)                      ((x) << 0x0E)              // Size (0 for 16-bit, 1 for 32)
#define SEG_GRAN(x)                      ((x) << 0x0F)              // Granularity (0 for 1B - 1MB, 1 for 4KB - 4GB)
#define SEG_PRIV(x)                      (((x) & 0x03) << 0x05)     // Set privilege level (0 - 3)

//////////////////////////////////////////////////////////////////////////
// Code/Data
//////////////////////////////////////////////////////////////////////////
#define SEG_DATA_RD                      0x00                       // Read-Only
#define SEG_DATA_RDA                     0x01                       // Read-Only, accessed
#define SEG_DATA_RDWR                    0x02                       // Read/Write
#define SEG_DATA_RDWRA                   0x03                       // Read/Write, accessed
#define SEG_DATA_RDEXPD                  0x04                       // Read-Only, expand-down
#define SEG_DATA_RDEXPDA                 0x05                       // Read-Only, expand-down, accessed
#define SEG_DATA_RDWREXPD                0x06                       // Read/Write, expand-down
#define SEG_DATA_RDWREXPDA               0x07                       // Read/Write, expand-down, accessed
#define SEG_CODE_EX                      0x08                       // Execute-Only
#define SEG_CODE_EXA                     0x09                       // Execute-Only, accessed
#define SEG_CODE_EXRD                    0x0A                       // Execute/Read
#define SEG_CODE_EXRDA                   0x0B                       // Execute/Read, accessed
#define SEG_CODE_EXC                     0x0C                       // Execute-Only, conforming
#define SEG_CODE_EXCA                    0x0D                       // Execute-Only, conforming, accessed
#define SEG_CODE_EXRDC                   0x0E                       // Execute/Read, conforming
#define SEG_CODE_EXRDCA                  0x0F                       // Execute/Read, conforming, accessed
//////////////////////////////////////////////////////////////////////////
// System type x86
//////////////////////////////////////////////////////////////////////////
#define SEG_SYS_RESERVED_0               0x00                       // Reserved
#define SEG_SYS_TSS16_AVL                0x01                       // 16-bit TSS (Available)
#define SEG_SYS_LDT                      0x02                       // LDT
#define SEG_SYS_TSS16_BUSY               0x03                       // 16-bit TSS (Busy)
#define SEG_SYS_CALLGATE_16              0x04                       // 16-bit Call Gate
#define SEG_SYS_TASKGATE                 0x05                       // Task Gate
#define SEG_SYS_INT_GATE_16              0x06                       // 16-bit Interrupt Gate
#define SEG_SYS_TRAP_GATE_16             0x07                       // 16-bit Trap Gate
#define SEG_SYS_RESERVED_8               0x08                       // Reserved
#define SEG_SYS_TSS32_AVL                0x09                       // 32-bit TSS (Available)
#define SEG_SYS_RESERVED_10              0x0A                       // Reserved
#define SEG_SYS_TSS32_BUSY               0x0B                       // 32-bit TSS (Busy)
#define SEG_SYS_CALLGATE_32              0x0C                       // 32-bit Call Gate
#define SEG_SYS_RESERVED_13              0x0D                       // Reserved
#define SEG_SYS_INT_GATE_32              0x0E                       // 32-bit Interrupt Gate
#define SEG_SYS_TRAP_GATE_32             0x0F                       // 32-bit Trap Gate
//////////////////////////////////////////////////////////////////////////
// System type x64 (yes, same names)
//////////////////////////////////////////////////////////////////////////
#define SEG_SYS_UPPER_8_BYTE             0x00                       // Upper 8 byte of an 16-byte descriptor
#define SEG_SYS_RESERVED_1               0x01                       // Reserved
#define SEG_SYS_LDT                      0x02                       // LDT
#define SEG_SYS_RESERVED_3               0x03                       // Reserved
#define SEG_SYS_RESERVED_4               0x04                       // Reserved
#define SEG_SYS_RESERVED_5               0x05                       // Reserved
#define SEG_SYS_RESERVED_6               0x06                       // Reserved
#define SEG_SYS_RESERVED_7               0x07                       // Reserved
#define SEG_SYS_RESERVED_8               0x08                       // Reserved
#define SEG_SYS_TSS64_AVL                0x09                       // 64-bit TSS (Available)
#define SEG_SYS_RESERVED_10              0x0A                       // Reserved
#define SEG_SYS_TSS64_BUSY               0x0B                       // 64-bit TSS (Busy)
#define SEG_SYS_CALLGATE_64              0x0C                       // 64-bit Call Gate
#define SEG_SYS_RESERVED_13              0x0D                       // Reserved
#define SEG_SYS_INT_GATE_64              0x0E                       // 64-bit Interrupt Gate
#define SEG_SYS_TRAP_GATE_64             0x0F                       // 64-bit Trap Gate
//////////////////////////////////////////////////////////////////////////
}   // namespace wa

#endif  // SRC_DDK_H_
