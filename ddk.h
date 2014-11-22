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

#ifndef _DDK_H_
#define _DDK_H_

#define WXP_VER         2600 // Windows XP
#define W2K3_VER        3790 // Windows 2003
#define VISTA_RTM_VER   6000 // Windows Vista SP0
#define VISTA_SP1_VER   6001 // Windows Vista SP1 / Windows Server 2008 SP1
#define VISTA_SP2_VER   6002 // Windows Vista SP2 / Windows Server 2008 SP2
#define W7RTM_VER       7600 // Windows 7 SP0
#define W7SP1_VER       7601 // Windows 7 SP1
#define W8RTM_VER       9200 // Windows 8 SP0
#define W81RTM_VER      9600 // Windows 8.1 RTM

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

enum OBJ_HEADER_INFO_FLAG
{
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag    = 0x2,
    HeaderHandleInfoFlag  = 0x4,
    HeaderQuotaInfoFlag   = 0x8,
    HeaderProcessInfoFlag = 0x10
};

#define NOTIFY_DEVICE_CLASS_HASH_BUCKETS 13
#define MAX_FAST_REFS_X64                15
#define MAX_FAST_REFS_X86                7

#define SYSENTER_CS_MSR                  0x174
#define SYSENTER_ESP_MSR                 0x175
#define SYSENTER_EIP_MSR                 0x176

#define MAKEULONG( x, y ) ( ( ( ( (unsigned long )( x ) ) << 16 ) & 0xFFFF0000 ) | ( (unsigned long )( y ) & 0xFFFF ) )

typedef union _KIDT_HANDLER_ADDRESS
{
    struct
    {
        unsigned short OffsetLow;
        unsigned short OffsetMiddle;
        unsigned long  OffsetHigh;
    };

    unsigned __int64   Address;
} KIDT_HANDLER_ADDRESS, *PKIDT_HANDLER_ADDRESS;

#endif // _DDK_H_