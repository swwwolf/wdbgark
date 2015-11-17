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

//////////////////////////////////////////////////////////////////////////
// IDT entry
//////////////////////////////////////////////////////////////////////////
struct _KIDTENTRY {

    unsigned short Offset;
    unsigned short Selector;
    unsigned short Access;
    unsigned short ExtendedOffset;
};
// <size 0x08>
//////////////////////////////////////////////////////////////////////////
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
//////////////////////////////////////////////////////////////////////////
// Interrupt entry
// Just an example. Note Windows 8.1 x86 (!!!) nt!_KPRCB structure (VectorToInterruptObject offset)!
//
// Windows 7 x86
//////////////////////////////////////////////////////////////////////////
struct _KINTERRUPT {

    short Type;
    short Size;
    struct _LIST_ENTRY InterruptListEntry;
    unsigned char  (ServiceRoutine*)(struct _KINTERRUPT*, void*);
    unsigned char  (MessageServiceRoutine*)(struct _KINTERRUPT*, void*, unsigned long);
    unsigned long MessageIndex;
    void* ServiceContext;
    unsigned long SpinLock;
    unsigned long TickCount;
    unsigned long* ActualLock;
    void  (DispatchAddress*)();
    unsigned long Vector;
    unsigned char Irql;
    unsigned char SynchronizeIrql;
    unsigned char FloatingSave;
    unsigned char Connected;
    unsigned long Number;
    unsigned char ShareVector;
    char Pad[3];
    enum _KINTERRUPT_MODE Mode;
    enum _KINTERRUPT_POLARITY Polarity;
    unsigned long ServiceCount;
    unsigned long DispatchCount;
    unsigned __int64 Rsvd1;
    unsigned long DispatchCode[135];
};
// <size 0x278>
//////////////////////////////////////////////////////////////////////////
// Windows 7 x64
//////////////////////////////////////////////////////////////////////////
struct _KINTERRUPT {

    short Type;
    short Size;
    struct _LIST_ENTRY InterruptListEntry;
    unsigned char  (ServiceRoutine*)(struct _KINTERRUPT*, void*);
    unsigned char  (MessageServiceRoutine*)(struct _KINTERRUPT*, void*, unsigned long);
    unsigned long MessageIndex;
    void* ServiceContext;
    unsigned __int64 SpinLock;
    unsigned long TickCount;
    unsigned __int64* ActualLock;
    void  (DispatchAddress*)();
    unsigned long Vector;
    unsigned char Irql;
    unsigned char SynchronizeIrql;
    unsigned char FloatingSave;
    unsigned char Connected;
    unsigned long Number;
    unsigned char ShareVector;
    char Pad[3];
    enum _KINTERRUPT_MODE Mode;
    enum _KINTERRUPT_POLARITY Polarity;
    unsigned long ServiceCount;
    unsigned long DispatchCount;
    unsigned __int64 Rsvd1;
    struct _KTRAP_FRAME* TrapFrame;
    void* Reserved;
    unsigned long DispatchCode[4];
};
// <size 0xa0>
//////////////////////////////////////////////////////////////////////////
// Windows 8.1.x x86 only
//////////////////////////////////////////////////////////////////////////
struct _KPRCB {
    unsigned short MinorVersion;
    unsigned short MajorVersion;
    struct _KTHREAD* CurrentThread;
    struct _KTHREAD* NextThread;
    struct _KTHREAD* IdleThread;
    unsigned char LegacyNumber;
    unsigned char NestingLevel;
    unsigned short BuildType;
    char CpuType;
    char CpuID;
    unsigned short CpuStep;
    unsigned char CpuStepping;
    unsigned char CpuModel;
    struct _KPROCESSOR_STATE ProcessorState;
    struct _KNODE* ParentNode;
    char* PriorityState;
    unsigned long KernelReserved[14];
    unsigned long HalReserved[16];
    unsigned long CFlushSize;
    unsigned char CoresPerPhysicalProcessor;
    unsigned char LogicalProcessorsPerCore;
    unsigned char CpuVendor;
    unsigned char PrcbPad0[1];
    unsigned long MHz;
    unsigned char GroupIndex;
    unsigned char Group;
    unsigned char PrcbPad05[2];
    unsigned long GroupSetMember;
    unsigned long Number;
    unsigned char ClockOwner;
    unsigned char PendingTickFlags;
    unsigned char PendingTick:0:1;
    unsigned char PendingBackupTick:1:1;
    unsigned char PrcbPad10[70];
    struct _KSPIN_LOCK_QUEUE LockQueue[17];
    unsigned long InterruptCount;
    unsigned long KernelTime;
    unsigned long UserTime;
    unsigned long DpcTime;
    unsigned long DpcTimeCount;
    unsigned long InterruptTime;
    unsigned long AdjustDpcThreshold;
    unsigned long PageColor;
    unsigned char DebuggerSavedIRQL;
    unsigned char NodeColor;
    unsigned char PrcbPad20[6];
    unsigned long NodeShiftedColor;
    unsigned long SecondaryColorMask;
    unsigned long DpcTimeLimit;
    unsigned long PrcbPad21[3];
    unsigned long CcFastReadNoWait;
    unsigned long CcFastReadWait;
    unsigned long CcFastReadNotPossible;
    unsigned long CcCopyReadNoWait;
    unsigned long CcCopyReadWait;
    unsigned long CcCopyReadNoWaitMiss;
    long MmSpinLockOrdering;
    long IoReadOperationCount;
    long IoWriteOperationCount;
    long IoOtherOperationCount;
    union _LARGE_INTEGER IoReadTransferCount;
    union _LARGE_INTEGER IoWriteTransferCount;
    union _LARGE_INTEGER IoOtherTransferCount;
    unsigned long CcFastMdlReadNoWait;
    unsigned long CcFastMdlReadWait;
    unsigned long CcFastMdlReadNotPossible;
    unsigned long CcMapDataNoWait;
    unsigned long CcMapDataWait;
    unsigned long CcPinMappedDataCount;
    unsigned long CcPinReadNoWait;
    unsigned long CcPinReadWait;
    unsigned long CcMdlReadNoWait;
    unsigned long CcMdlReadWait;
    unsigned long CcLazyWriteHotSpots;
    unsigned long CcLazyWriteIos;
    unsigned long CcLazyWritePages;
    unsigned long CcDataFlushes;
    unsigned long CcDataPages;
    unsigned long CcLostDelayedWrites;
    unsigned long CcFastReadResourceMiss;
    unsigned long CcCopyReadWaitMiss;
    unsigned long CcFastMdlReadResourceMiss;
    unsigned long CcMapDataNoWaitMiss;
    unsigned long CcMapDataWaitMiss;
    unsigned long CcPinReadNoWaitMiss;
    unsigned long CcPinReadWaitMiss;
    unsigned long CcMdlReadNoWaitMiss;
    unsigned long CcMdlReadWaitMiss;
    unsigned long CcReadAheadIos;
    unsigned long KeAlignmentFixupCount;
    unsigned long KeExceptionDispatchCount;
    unsigned long KeSystemCalls;
    unsigned long AvailableTime;
    unsigned long PrcbPad22[2];
    struct _PP_LOOKASIDE_LIST PPLookasideList[16];
    struct _GENERAL_LOOKASIDE_POOL PPNxPagedLookasideList[32];
    struct _GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
    struct _GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
    unsigned long PacketBarrier;
    long ReverseStall;
    void* IpiFrame;
    unsigned char PrcbPad3[52];
    void* CurrentPacket[3];
    unsigned long TargetSet;
    void  (WorkerRoutine*)(void*, void*, void*, void*);
    unsigned long IpiFrozen;
    unsigned char PrcbPad4[40];
    unsigned long RequestSummary;
    struct _KPRCB* SignalDone;
    unsigned char PrcbPad50[40];
    unsigned long InterruptLastCount;
    unsigned long InterruptRate;
    unsigned long DeviceInterrupts;
    void* IsrDpcStats;
    struct _KDPC_DATA DpcData[2];
    void* DpcStack;
    long MaximumDpcQueueDepth;
    unsigned long DpcRequestRate;
    unsigned long MinimumDpcRate;
    unsigned long DpcLastCount;
    unsigned long PrcbLock;
    struct _KGATE DpcGate;
    unsigned char ThreadDpcEnable;
    unsigned char QuantumEnd;
    unsigned char DpcRoutineActive;
    unsigned char IdleSchedule;
    long DpcRequestSummary;
    short DpcRequestSlot[2];
    short NormalDpcState;
    short ThreadDpcState;
    unsigned long DpcNormalProcessingActive:0:1;
    unsigned long DpcNormalProcessingRequested:1:1;
    unsigned long DpcNormalThreadSignal:2:1;
    unsigned long DpcNormalTimerExpiration:3:1;
    unsigned long DpcNormalDpcPresent:4:1;
    unsigned long DpcNormalLocalInterrupt:5:1;
    unsigned long DpcNormalSpare:6:a;
    unsigned long DpcThreadActive:10:1;
    unsigned long DpcThreadRequested:11:1;
    unsigned long DpcThreadSpare:12:e;
    unsigned long LastTimerHand;
    unsigned long LastTick;
    unsigned long PeriodicCount;
    unsigned long PeriodicBias;
    unsigned long ClockInterrupts;
    unsigned long ReadyScanTick;
    unsigned char GroupSchedulingOverQuota;
    unsigned char PrcbPad41[3];
    struct _KTIMER_TABLE TimerTable;
    struct _KDPC CallDpc;
    long ClockKeepAlive;
    unsigned char PrcbPad6[4];
    long DpcWatchdogPeriod;
    long DpcWatchdogCount;
    long KeSpinLockOrdering;
    unsigned long PrcbPad70[1];
    unsigned long QueueIndex;
    struct _SINGLE_LIST_ENTRY DeferredReadyListHead;
    unsigned long ReadySummary;
    long AffinitizedSelectionMask;
    unsigned long WaitLock;
    struct _LIST_ENTRY WaitListHead;
    unsigned long ScbOffset;
    unsigned __int64 StartCycles;
    unsigned __int64 GenerationTarget;
    unsigned __int64 CycleTime;
    unsigned __int64 AffinitizedCycles;
    unsigned long HighCycleTime;
    unsigned long PrcbPad71;
    struct _LIST_ENTRY DispatcherReadyListHead[32];
    void* ChainedInterruptList;
    long LookasideIrpFloat;
    struct _RTL_RB_TREE ScbQueue;
    struct _LIST_ENTRY ScbList;
    long MmPageFaultCount;
    long MmCopyOnWriteCount;
    long MmTransitionCount;
    long MmCacheTransitionCount;
    long MmDemandZeroCount;
    long MmPageReadCount;
    long MmPageReadIoCount;
    long MmCacheReadCount;
    long MmCacheIoCount;
    long MmDirtyPagesWriteCount;
    long MmDirtyWriteIoCount;
    long MmMappedPagesWriteCount;
    long MmMappedWriteIoCount;
    unsigned long CachedCommit;
    unsigned long CachedResidentAvailable;
    void* HyperPte;
    unsigned char PrcbPad8[4];
    unsigned char VendorString[13];
    unsigned char InitialApicId;
    unsigned char LogicalProcessorsPerPhysicalProcessor;
    unsigned char PrcbPad9[5];
    unsigned long FeatureBits;
    union _LARGE_INTEGER UpdateSignature;
    unsigned __int64 IsrTime;
    unsigned long PrcbPad90[2];
    struct _PROCESSOR_POWER_STATE PowerState;
    unsigned long PrcbPad91[13];
    struct _KDPC DpcWatchdogDpc;
    struct _KTIMER DpcWatchdogTimer;
    union _SLIST_HEADER HypercallPageList;
    void* HypercallPageVirtual;
    void* VirtualApicAssist;
    unsigned __int64* StatisticsPage;
    struct _CACHE_DESCRIPTOR Cache[5];
    unsigned long CacheCount;
    struct _KAFFINITY_EX PackageProcessorSet;
    unsigned long SharedReadyQueueMask;
    struct _KSHARED_READY_QUEUE* SharedReadyQueue;
    unsigned long CoreProcessorSet;
    unsigned long ScanSiblingMask;
    unsigned long LLCMask;
    unsigned long CacheProcessorMask[5];
    unsigned long ScanSiblingIndex;
    void* WheaInfo;
    void* EtwSupport;
    union _SLIST_HEADER InterruptObjectPool;
    unsigned long SharedReadyQueueOffset;
    unsigned long PrcbPad92[2];
    unsigned long PteBitCache;
    unsigned long PteBitOffset;
    unsigned long PrcbPad93;
    struct _PROCESSOR_PROFILE_CONTROL_AREA* ProcessorProfileControlArea;
    void* ProfileEventIndexAddress;
    struct _KDPC TimerExpirationDpc;
    struct _SYNCH_COUNTERS SynchCounters;
    struct _FILESYSTEM_DISK_COUNTERS FsCounters;
    struct _CONTEXT* Context;
    unsigned long ContextFlagsInit;
    struct _XSAVE_AREA* ExtendedState;
    struct _KENTROPY_TIMING_STATE EntropyTimingState;
    void* IsrStack;
    struct _KINTERRUPT* VectorToInterruptObject[208];                           // <---------- !!!
    struct _SINGLE_LIST_ENTRY AbSelfIoBoostsList;
    struct _SINGLE_LIST_ENTRY AbPropagateBoostsList;
    struct _KDPC AbDpc;
};
// <size 0x4508>
//////////////////////////////////////////////////////////////////////////
// Windows 10 x64
//////////////////////////////////////////////////////////////////////////
struct _KPRCB {
    unsigned long MxCsr;
    unsigned char LegacyNumber;
    unsigned char ReservedMustBeZero;
    unsigned char InterruptRequest;
    unsigned char IdleHalt;
    struct _KTHREAD* CurrentThread;
    struct _KTHREAD* NextThread;
    struct _KTHREAD* IdleThread;
    unsigned char NestingLevel;
    unsigned char ClockOwner;
    unsigned char PendingTickFlags;
    unsigned char PendingTick : 0 : 1;
    unsigned char PendingBackupTick : 1 : 1;
    unsigned char IdleState;
    unsigned long Number;
    unsigned __int64 RspBase;
    unsigned __int64 PrcbLock;
    char* PriorityState;
    struct _KPROCESSOR_STATE ProcessorState;
    char CpuType;
    char CpuID;
    unsigned short CpuStep;
    unsigned char CpuStepping;
    unsigned char CpuModel;
    unsigned long MHz;
    unsigned __int64 HalReserved[8];
    unsigned short MinorVersion;
    unsigned short MajorVersion;
    unsigned char BuildType;
    unsigned char CpuVendor;
    unsigned char CoresPerPhysicalProcessor;
    unsigned char LogicalProcessorsPerCore;
    struct _KNODE* ParentNode;
    unsigned __int64 GroupSetMember;
    unsigned char Group;
    unsigned char GroupIndex;
    unsigned char PrcbPad05[2];
    unsigned long InitialApicId;
    unsigned long ScbOffset;
    unsigned long ApicMask;
    void* AcpiReserved;
    unsigned long CFlushSize;
    unsigned long PrcbPad10;
    struct _KSPIN_LOCK_QUEUE LockQueue[17];
    struct _PP_LOOKASIDE_LIST PPLookasideList[16];
    struct _GENERAL_LOOKASIDE_POOL PPNxPagedLookasideList[32];
    struct _GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
    struct _GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
    unsigned __int64 PrcbPad20;
    struct _SINGLE_LIST_ENTRY DeferredReadyListHead;
    long MmPageFaultCount;
    long MmCopyOnWriteCount;
    long MmTransitionCount;
    long MmDemandZeroCount;
    long MmPageReadCount;
    long MmPageReadIoCount;
    long MmDirtyPagesWriteCount;
    long MmDirtyWriteIoCount;
    long MmMappedPagesWriteCount;
    long MmMappedWriteIoCount;
    unsigned long KeSystemCalls;
    unsigned long KeContextSwitches;
    unsigned short LdtSelector;
    unsigned short PrcbPad40;
    unsigned long CcFastReadNoWait;
    unsigned long CcFastReadWait;
    unsigned long CcFastReadNotPossible;
    unsigned long CcCopyReadNoWait;
    unsigned long CcCopyReadWait;
    unsigned long CcCopyReadNoWaitMiss;
    long IoReadOperationCount;
    long IoWriteOperationCount;
    long IoOtherOperationCount;
    union _LARGE_INTEGER IoReadTransferCount;
    union _LARGE_INTEGER IoWriteTransferCount;
    union _LARGE_INTEGER IoOtherTransferCount;
    long PacketBarrier;
    long TargetCount;
    unsigned long IpiFrozen;
    void* IsrDpcStats;
    unsigned long DeviceInterrupts;
    long LookasideIrpFloat;
    unsigned long InterruptLastCount;
    unsigned long InterruptRate;
    unsigned long PrcbPad41[22];
    struct _KDPC_DATA DpcData[2];
    void* DpcStack;
    long MaximumDpcQueueDepth;
    unsigned long DpcRequestRate;
    unsigned long MinimumDpcRate;
    unsigned long DpcLastCount;
    unsigned char ThreadDpcEnable;
    unsigned char QuantumEnd;
    unsigned char DpcRoutineActive;
    unsigned char IdleSchedule;
    long DpcRequestSummary;
    short DpcRequestSlot[2];
    short NormalDpcState;
    short ThreadDpcState;
    unsigned long DpcNormalProcessingActive : 0 : 1;
    unsigned long DpcNormalProcessingRequested : 1 : 1;
    unsigned long DpcNormalThreadSignal : 2 : 1;
    unsigned long DpcNormalTimerExpiration : 3 : 1;
    unsigned long DpcNormalDpcPresent : 4 : 1;
    unsigned long DpcNormalLocalInterrupt : 5 : 1;
    unsigned long DpcNormalSpare : 6 : a;
    unsigned long DpcThreadActive : 10 : 1;
    unsigned long DpcThreadRequested : 11 : 1;
    unsigned long DpcThreadSpare : 12 : e;
    unsigned long LastTimerHand;
    unsigned long LastTick;
    unsigned long ClockInterrupts;
    unsigned long ReadyScanTick;
    void* InterruptObject[256];                                                 // <---------- !!!
    struct _KTIMER_TABLE TimerTable;
    struct _KGATE DpcGate;
    void* PrcbPad52;
    struct _KDPC CallDpc;
    long ClockKeepAlive;
    unsigned char PrcbPad60[2];
    unsigned short NmiActive;
    long DpcWatchdogPeriod;
    long DpcWatchdogCount;
    long KeSpinLockOrdering;
    unsigned long PrcbPad70[1];
    void* CachedPtes;
    struct _LIST_ENTRY WaitListHead;
    unsigned __int64 WaitLock;
    unsigned long ReadySummary;
    long AffinitizedSelectionMask;
    unsigned long QueueIndex;
    unsigned long PrcbPad75[3];
    struct _KDPC TimerExpirationDpc;
    struct _RTL_RB_TREE ScbQueue;
    struct _LIST_ENTRY DispatcherReadyListHead[32];
    unsigned long InterruptCount;
    unsigned long KernelTime;
    unsigned long UserTime;
    unsigned long DpcTime;
    unsigned long InterruptTime;
    unsigned long AdjustDpcThreshold;
    unsigned char DebuggerSavedIRQL;
    unsigned char GroupSchedulingOverQuota;
    unsigned char DeepSleep;
    unsigned char PrcbPad80[5];
    unsigned long DpcTimeCount;
    unsigned long DpcTimeLimit;
    unsigned long PeriodicCount;
    unsigned long PeriodicBias;
    unsigned long AvailableTime;
    unsigned long KeExceptionDispatchCount;
    unsigned __int64 StartCycles;
    unsigned __int64 TaggedCyclesStart;
    unsigned __int64 TaggedCycles[2];
    unsigned __int64 GenerationTarget;
    unsigned __int64 AffinitizedCycles;
    unsigned long PrcbPad81[29];
    long MmSpinLockOrdering;
    unsigned long PageColor;
    unsigned long NodeColor;
    unsigned long NodeShiftedColor;
    unsigned long SecondaryColorMask;
    unsigned long PrcbPad83;
    unsigned __int64 CycleTime;
    unsigned __int64 Cycles[4][2];
    unsigned long PrcbPad84[16];
    unsigned long CcFastMdlReadNoWait;
    unsigned long CcFastMdlReadWait;
    unsigned long CcFastMdlReadNotPossible;
    unsigned long CcMapDataNoWait;
    unsigned long CcMapDataWait;
    unsigned long CcPinMappedDataCount;
    unsigned long CcPinReadNoWait;
    unsigned long CcPinReadWait;
    unsigned long CcMdlReadNoWait;
    unsigned long CcMdlReadWait;
    unsigned long CcLazyWriteHotSpots;
    unsigned long CcLazyWriteIos;
    unsigned long CcLazyWritePages;
    unsigned long CcDataFlushes;
    unsigned long CcDataPages;
    unsigned long CcLostDelayedWrites;
    unsigned long CcFastReadResourceMiss;
    unsigned long CcCopyReadWaitMiss;
    unsigned long CcFastMdlReadResourceMiss;
    unsigned long CcMapDataNoWaitMiss;
    unsigned long CcMapDataWaitMiss;
    unsigned long CcPinReadNoWaitMiss;
    unsigned long CcPinReadWaitMiss;
    unsigned long CcMdlReadNoWaitMiss;
    unsigned long CcMdlReadWaitMiss;
    unsigned long CcReadAheadIos;
    long MmCacheTransitionCount;
    long MmCacheReadCount;
    long MmCacheIoCount;
    unsigned long PrcbPad91[3];
    struct _PROCESSOR_POWER_STATE PowerState;
    struct _LIST_ENTRY ScbList;
    unsigned long PrcbPad92[7];
    unsigned long KeAlignmentFixupCount;
    struct _KDPC DpcWatchdogDpc;
    struct _KTIMER DpcWatchdogTimer;
    struct _CACHE_DESCRIPTOR Cache[5];
    unsigned long CacheCount;
    unsigned long CachedCommit;
    unsigned long CachedResidentAvailable;
    void* HyperPte;
    void* WheaInfo;
    void* EtwSupport;
    union _SLIST_HEADER InterruptObjectPool;
    union _SLIST_HEADER HypercallPageList;
    void* HypercallCachedPages;
    void* VirtualApicAssist;
    unsigned __int64* StatisticsPage;
    struct _KAFFINITY_EX PackageProcessorSet;
    unsigned __int64 SharedReadyQueueMask;
    struct _KSHARED_READY_QUEUE* SharedReadyQueue;
    unsigned long SharedQueueScanOwner;
    unsigned long ScanSiblingIndex;
    unsigned __int64 CoreProcessorSet;
    unsigned __int64 ScanSiblingMask;
    unsigned __int64 LLCMask;
    unsigned __int64 CacheProcessorMask[5];
    struct _PROCESSOR_PROFILE_CONTROL_AREA* ProcessorProfileControlArea;
    void* ProfileEventIndexAddress;
    unsigned __int64 PrcbPad94[11];
    struct _SYNCH_COUNTERS SynchCounters;
    unsigned __int64 PteBitCache;
    unsigned long PteBitOffset;
    struct _FILESYSTEM_DISK_COUNTERS FsCounters;
    unsigned char VendorString[13];
    unsigned char PrcbPad100[3];
    unsigned __int64 FeatureBits;
    unsigned long PrcbPad110;
    union _LARGE_INTEGER UpdateSignature;
    struct _CONTEXT* Context;
    unsigned long ContextFlagsInit;
    struct _XSAVE_AREA* ExtendedState;
    void* IsrStack;
    struct _KENTROPY_TIMING_STATE EntropyTimingState;
    struct _SINGLE_LIST_ENTRY AbSelfIoBoostsList;
    struct _SINGLE_LIST_ENTRY AbPropagateBoostsList;
    struct _KDPC AbDpc;
    struct _IOP_IRP_STACK_PROFILER IoIrpStackProfilerCurrent;
    struct _IOP_IRP_STACK_PROFILER IoIrpStackProfilerPrevious;
    struct _KSHARED_READY_QUEUE LocalSharedReadyQueue;
    struct _KTIMER_EXPIRATION_TRACE TimerExpirationTrace[16];
    unsigned long TimerExpirationTraceCount;
    void* ExSaPageArray;
    struct _REQUEST_MAILBOX* Mailbox;
    struct _REQUEST_MAILBOX RequestMailbox[1];
};
// <size 0x6900>
//////////////////////////////////////////////////////////////////////////
x86:
    | StartUnexpectedRange |                       | EndUnexpectedRange |
    nt!KiStartUnexpectedRange < unexpected entry < nt!KiEndUnexpectedRange
x64:
    nt!KxUnexpectedInterrupt0 < unexpected entry < nt!KxUnexpectedInterrupt0 + 0xFF * sizeof( nt!_UNEXPECTED_INTERRUPT )

Algorithm:

    walk IDT from 0 to 0xFF and get every entry

    vector = 0;
    for idt_entry in IDT (vector++) // x86 & x64
    {
        _KINTERRUPT kintr = 0;

        if ( idt_entry < StartUnexpectedRange || idt_entry > EndUnexpectedRange )
        {
            if ( x64 || !VectorToInterruptObject_offset ) // x64 or x86 nt-build < W8.1
            {
                kintr = idt_entry - FIELD_OFFSET( _KINTERRUPT, DispatchCode );

                if ( kintr->Type != nt!_KOBJECTS::InterruptObject )
                    kintr = 0;
            }
        }
        else if ( x86 && VectorToInterruptObject_offset ) // W8.1+ x86
        {
            if ( vector >= PRIMARY_VECTOR_BASE )
            {
                kintr = nt!_KPCR->_KPRCB->VectorToInterruptObject[ vector - PRIMARY_VECTOR_BASE ];
            }
        }

        then walk _KINTERRUPT->InterruptListEntry;
    }
//////////////////////////////////////////////////////////////////////////
*/

#include <vector>
#include <string>
#include <sstream>
#include <memory>

#include "wdbgark.hpp"
#include "analyze.hpp"
#include "manipulators.hpp"

namespace wa {
//////////////////////////////////////////////////////////////////////////
typedef struct IdtSupportTag {
    unsigned __int64 start_unexpected_range;
    unsigned __int64 end_unexpected_range;
    unsigned __int32 vector_to_interrupt_object;
    unsigned __int32 dispatch_code_offset;
    unsigned __int32 message_service_offset;
    unsigned __int32 service_routine_offset;
    unsigned __int32 interrupt_list_entry;
    unsigned __int32 interrupt_object_offset;
} IdtSupport;

bool InitIdtSupport(const unsigned __int32 strict_minor_build, IdtSupport* support_info);
//////////////////////////////////////////////////////////////////////////
// TODO(swwwolf): REFACTORING!!!
EXT_COMMAND(wa_idt, "Output processors IDT", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Dumping IDTs" << endlout;

    IdtSupport support_info = {0};

    if ( !InitIdtSupport(m_system_ver->GetStrictVer(), &support_info) ) {
        err << wa::showminus << __FUNCTION__ << ": InitIdtSupport failed" << endlerr;
    }

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeIDT);
    display->PrintHeader();

    try {
        for ( unsigned int i = 0; i < g_Ext->m_NumProcessors; i++ ) {
            unsigned __int64 kpcr_offset     = 0;
            unsigned __int64 idt_entry_start = 0;
            unsigned __int32 idt_entry_size  = 0;

            HRESULT result = g_Ext->m_Data->ReadProcessorSystemData(i,
                                                                    DEBUG_DATA_KPCR_OFFSET,
                                                                    &kpcr_offset,
                                                                    static_cast<unsigned __int32>(sizeof(kpcr_offset)),
                                                                    NULL);

            if ( !SUCCEEDED(result) ) {
                err << wa::showminus << __FUNCTION__ << ": ReadProcessorSystemData failed with error = " << result;
                err << endlerr;
                break;
            }

            ExtRemoteTyped pcr("nt!_KPCR", kpcr_offset, false, NULL, NULL);

            if ( m_is_cur_machine64 ) {
                idt_entry_start = pcr.Field("IdtBase").GetPtr();    // _KIDTENTRY64*
                idt_entry_size = GetTypeSize("nt!_KIDTENTRY64");
            } else {
                idt_entry_start = pcr.Field("IDT").GetPtr();        // _KIDTENTRY*
                idt_entry_size = GetTypeSize("nt!_KIDTENTRY");
            }

            for ( unsigned __int32 j = 0; j <= MAXIMUM_IDTVECTOR; j++ ) {
                unsigned __int64 isr_address = 0;

                std::stringstream processor_index;
                processor_index << std::setw(2) << i << " / " << std::setw(2) << std::hex << j;

                std::stringstream info;

                if ( m_is_cur_machine64 )
                    info << std::setw(52);
                else
                    info << std::setw(50);

                if ( m_is_cur_machine64 ) {
                    KIDT_HANDLER_ADDRESS idt_handler;

                    ExtRemoteTyped idt_entry("nt!_KIDTENTRY64",
                                             idt_entry_start + j * idt_entry_size,
                                             false,
                                             NULL,
                                             NULL);

                    idt_handler.off.OffsetLow = idt_entry.Field("OffsetLow").GetUshort();
                    idt_handler.off.OffsetMiddle = idt_entry.Field("OffsetMiddle").GetUshort();
                    idt_handler.off.OffsetHigh = idt_entry.Field("OffsetHigh").GetUlong();

                    isr_address = idt_handler.Address;

                    info << "<exec cmd=\"dx -r1 *(nt!_KIDTENTRY64 *)" << std::hex << std::showbase;
                    info << idt_entry.m_Offset << "\">dx" << "</exec>" << " ";
                } else {
                    ExtRemoteTyped idt_entry("nt!_KIDTENTRY",
                                             idt_entry_start + j * idt_entry_size,
                                             false,
                                             NULL,
                                             NULL);

                    isr_address = static_cast<unsigned __int64>(MAKEULONG(idt_entry.Field("ExtendedOffset").GetUshort(),
                                                                          idt_entry.Field("Offset").GetUshort()));

                    std::stringstream expression;
                    expression << std::hex << std::showbase <<  isr_address;

                    isr_address = g_Ext->EvalExprU64(expression.str().c_str());

                    info << "<exec cmd=\"dx -r1 *(nt!_KIDTENTRY *)" << std::hex << std::showbase;
                    info << idt_entry.m_Offset << "\">dx" << "</exec>" << " ";
                }

                info << "<exec cmd=\"dx -r1 *(nt!_KPCR *)" << std::hex << std::showbase << kpcr_offset;
                info << "\">pcr" << "</exec>" << " ";
                info << "<exec cmd=\"dx -r1 *(nt!_KPRCB *)" << std::hex << std::showbase << pcr.Field("Prcb").m_Offset;
                info << "\">prcb" << "</exec>";

                // display idt entry
                display->Analyze(isr_address, processor_index.str(), info.str());

                if ( !(isr_address >> 32) ) {
                    display->PrintFooter();
                    continue;
                }

                // now deal with _KINTERRUPTs
                ExtRemoteTyped interrupt;
                bool           valid_interrupt = false;

                if ( isr_address < support_info.start_unexpected_range ||
                     isr_address > support_info.end_unexpected_range ||
                     support_info.interrupt_object_offset ) {
                    if ( m_is_cur_machine64 ||
                         !support_info.vector_to_interrupt_object ||
                         support_info.interrupt_object_offset ) {
                        ExtRemoteTyped loc_interrupt;

                        if ( support_info.interrupt_object_offset ) {
                            loc_interrupt.Set("nt!_KINTERRUPT",
                                              ExtRemoteData(pcr.Field("Prcb.InterruptObject").m_Offset + \
                                              j * m_PtrSize, m_PtrSize).GetPtr(),
                                              false,
                                              NULL,
                                              NULL);
                        } else {
                            loc_interrupt.Set("nt!_KINTERRUPT",
                                              isr_address - support_info.dispatch_code_offset,
                                              false,
                                              NULL,
                                              NULL);
                        }

                        if ( loc_interrupt.m_Offset &&
                             loc_interrupt.Field("Type").GetUshort() == KOBJECTS::InterruptObject ) {
                            interrupt = loc_interrupt;
                            valid_interrupt = true;
                        }
                    }
                } else if ( !m_is_cur_machine64 && support_info.vector_to_interrupt_object ) {    // x86 Windows 8.1+
                    if ( j >= PRIMARY_VECTOR_BASE ) {
                        ExtRemoteTyped vector_to_interrupt = pcr.Field("PrcbData.VectorToInterruptObject");

                        ExtRemoteTyped tmp_interrupt =\
                            *vector_to_interrupt[static_cast<ULONG>(j - PRIMARY_VECTOR_BASE)];

                        if ( tmp_interrupt.m_Offset ) {
                            interrupt = tmp_interrupt;
                            valid_interrupt = true;
                        }
                    }
                }

                if ( valid_interrupt ) {
                    std::stringstream info_intr;
                    info_intr << std::setw(51);
                    info_intr << "<exec cmd=\"dx -r1 *(nt!_KINTERRUPT *)";
                    info_intr << std::hex << std::showbase << interrupt.m_Offset;
                    info_intr << "\">dx" << "</exec>" << " ";
                    info_intr << "<exec cmd=\"dx -r1 *(nt!_KPCR *)" << std::hex << std::showbase << kpcr_offset;
                    info_intr << "\">pcr" << "</exec>" << " ";
                    info_intr << "<exec cmd=\"dx -r1 *(nt!_KPRCB *)" << std::hex << std::showbase;
                    info_intr << pcr.Field("Prcb").m_Offset << "\">prcb" << "</exec>";

                    unsigned __int64 message_address = 0;

                    if ( support_info.message_service_offset )
                        message_address = interrupt.Field("MessageServiceRoutine").GetPtr();

                    if ( !message_address )
                        message_address = interrupt.Field("ServiceRoutine").GetPtr();

                    display->Analyze(message_address, processor_index.str(), info_intr.str());

                    walkresType    output_list;
                    ExtRemoteTyped list_entry = interrupt.Field("InterruptListEntry");

                    if ( support_info.message_service_offset ) {
                        WalkAnyListWithOffsetToRoutine("",
                                                       list_entry.m_Offset,
                                                       support_info.interrupt_list_entry,
                                                       true,
                                                       support_info.message_service_offset,
                                                       processor_index.str(),
                                                       "",
                                                       &output_list);
                    }

                    WalkAnyListWithOffsetToRoutine("",
                                                   list_entry.m_Offset,
                                                   support_info.interrupt_list_entry,
                                                   true,
                                                   support_info.service_routine_offset,
                                                   processor_index.str(),
                                                   "",
                                                   &output_list);

                    for ( const auto &walk_info : output_list ) {
                        if ( !walk_info.address )
                            continue;

                        std::stringstream info_intr_list;
                        info_intr_list << std::setw(51);

                        info_intr_list << "<exec cmd=\"dx -r1 *(nt!_KINTERRUPT *)";
                        info_intr_list << std::hex << std::showbase << walk_info.object_address;
                        info_intr_list << "\">dx" << "</exec>" << " ";
                        info_intr_list << "<exec cmd=\"dx -r1 *(nt!_KPCR *)" << std::hex << std::showbase;
                        info_intr_list << kpcr_offset << "\">pcr" << "</exec>" << " ";
                        info_intr_list << "<exec cmd=\"dx -r1 *(nt!_KPRCB *)" << std::hex << std::showbase;
                        info_intr_list << pcr.Field("Prcb").m_Offset << "\">prcb" << "</exec>";

                        display->Analyze(walk_info.address, walk_info.type, info_intr_list.str());
                    }

                    output_list.clear();
                }

                display->PrintFooter();
            }
        }
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

bool InitIdtSupport(const unsigned __int32 strict_minor_build, IdtSupport* support_info) {
    std::stringstream warn;
    std::stringstream err;

    if ( g_Ext->IsCurMachine64() ) {
        if ( !g_Ext->GetSymbolOffset("nt!KxUnexpectedInterrupt0", true, &support_info->start_unexpected_range) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get nt!KxUnexpectedInterrupt0" << endlerr;
            return false;
        }

        support_info->end_unexpected_range = support_info->start_unexpected_range +\
            ((MAXIMUM_IDTVECTOR + 1) * GetTypeSize("nt!_UNEXPECTED_INTERRUPT"));
    } else {
        if ( !g_Ext->GetSymbolOffset("nt!KiStartUnexpectedRange", true, &support_info->start_unexpected_range) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get nt!KiStartUnexpectedRange" << endlerr;
            return false;
        }

        if ( !g_Ext->GetSymbolOffset("nt!KiEndUnexpectedRange", true, &support_info->end_unexpected_range) ) {
            err << wa::showminus << __FUNCTION__ << ": failed to get nt!KiEndUnexpectedRange" << endlerr;
            return false;
        }
    }

    if ( g_Ext->IsCurMachine32()
         &&
         strict_minor_build >= W81RTM_VER
         &&
         GetFieldOffset("nt!_KPCR",
                        "PrcbData.VectorToInterruptObject",
                        reinterpret_cast<PULONG>(&support_info->vector_to_interrupt_object)) != 0 ) {
        warn << wa::showqmark << __FUNCTION__;
        warn << ": GetFieldOffset failed with PrcbData.VectorToInterruptObject" << endlwarn;
    }

    if ( strict_minor_build < W10RTM_VER ) {
        if ( (g_Ext->IsCurMachine64() || strict_minor_build <= W8RTM_VER)
              &&
              GetFieldOffset("nt!_KINTERRUPT",
                             "DispatchCode",
                             reinterpret_cast<PULONG>(&support_info->dispatch_code_offset)) != 0 ) {
            warn << wa::showqmark << __FUNCTION__ << ": GetFieldOffset failed with DispatchCode" << endlwarn;
        }
    } else if ( g_Ext->IsCurMachine64()
                &&
                GetFieldOffset("nt!_KPRCB",
                               "InterruptObject",
                               reinterpret_cast<PULONG>(&support_info->interrupt_object_offset)) != 0 ) {
        warn << wa::showqmark << __FUNCTION__ << ": GetFieldOffset failed with InterruptObject" << endlwarn;
    }

    if ( strict_minor_build >= VISTA_RTM_VER
         &&
         GetFieldOffset("nt!_KINTERRUPT",
                        "MessageServiceRoutine",
                        reinterpret_cast<PULONG>(&support_info->message_service_offset)) != 0 ) {
        warn << wa::showqmark << __FUNCTION__ << ": GetFieldOffset failed with MessageServiceRoutine" << endlwarn;
    }

    if ( GetFieldOffset("nt!_KINTERRUPT",
                        "ServiceRoutine",
                        reinterpret_cast<PULONG>(&support_info->service_routine_offset)) != 0 ) {
        warn << wa::showqmark << __FUNCTION__ << ": GetFieldOffset failed with ServiceRoutine" << endlwarn;
    }

    if ( GetFieldOffset("nt!_KINTERRUPT",
                        "InterruptListEntry",
                        reinterpret_cast<PULONG>(&support_info->interrupt_list_entry)) != 0 ) {
        warn << wa::showqmark << __FUNCTION__ << ": GetFieldOffset failed with InterruptListEntry" << endlwarn;
    }

    return true;
}

/*

//////////////////////////////////////////////////////////////////////////

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

full_address = selector.BaseLow | selector.HighWord.Bytes.BaseMid << 16 | selector.HighWord.Bytes.BaseHi << 24

*/

void DisplayOneGDTEntry(const std::string &gdt_entry_name,
                        const unsigned __int64 entry_address,
                        const unsigned __int32 gdt_entry_size,
                        const unsigned __int32 gdt_selector,
                        const unsigned __int32 cpu_idx,
                        const unsigned __int64 kpcr_offset,
                        std::unique_ptr<WDbgArkAnalyzeBase> const &display);

EXT_COMMAND(wa_gdt, "Output processors GDT", "") {
    RequireKernelMode();

    if ( !Init() )
        throw ExtStatusException(S_OK, "global init failed");

    out << wa::showplus << "Dumping GDTs" << endlout;

    auto display = WDbgArkAnalyzeBase::Create(m_sym_cache, WDbgArkAnalyzeBase::AnalyzeType::AnalyzeTypeGDT);
    display->PrintHeader();

    try {
        unsigned __int32 gdt_entry_size = 0;
        std::string gdt_entry_name;

        if ( m_is_cur_machine64 ) {
            gdt_entry_size = GetTypeSize("nt!_KGDTENTRY64");
            gdt_entry_name = "nt!_KGDTENTRY64";
        } else {
            gdt_entry_size = GetTypeSize("nt!_KGDTENTRY");
            gdt_entry_name = "nt!_KGDTENTRY";
        }

        for ( unsigned int cpu_idx = 0; cpu_idx < g_Ext->m_NumProcessors; cpu_idx++ ) {
            unsigned __int64 kpcr_offset     = 0;
            unsigned __int64 gdt_entry_start = 0;

            HRESULT result = g_Ext->m_Data->ReadProcessorSystemData(cpu_idx,
                                                                    DEBUG_DATA_KPCR_OFFSET,
                                                                    &kpcr_offset,
                                                                    sizeof(kpcr_offset),
                                                                    NULL);

            if ( !SUCCEEDED(result) ) {
                err << wa::showminus << __FUNCTION__ << ": CPU " << cpu_idx;
                err << ": ReadProcessorSystemData failed with error " << result << endlerr;
                continue;
            }

            ExtRemoteTyped pcr("nt!_KPCR", kpcr_offset, false, NULL, NULL);

            if ( m_is_cur_machine64 )
                gdt_entry_start = pcr.Field("GdtBase").GetPtr();    // _KGDTENTRY64*
            else
                gdt_entry_start = pcr.Field("GDT").GetPtr();        // _KGDTENTRY*

            unsigned __int32 gdt_selector = 0;

            if ( m_is_cur_machine64 ) {    // special case for x64
                for ( const auto gdt_selector_x64 : m_gdt_selectors ) {
                    DisplayOneGDTEntry(gdt_entry_name,
                                       gdt_entry_start + gdt_selector_x64,
                                       gdt_entry_size,
                                       gdt_selector_x64,
                                       cpu_idx,
                                       kpcr_offset,
                                       display);

                    gdt_selector = gdt_selector_x64 + gdt_entry_size;   // because last one is "normal"
                }
            }

            for ( ; gdt_selector < 0x400; gdt_selector += gdt_entry_size ) {
                DisplayOneGDTEntry(gdt_entry_name,
                                   gdt_entry_start + gdt_selector,
                                   gdt_entry_size,
                                   gdt_selector,
                                   cpu_idx,
                                   kpcr_offset,
                                   display);
            }
        }
    }
    catch ( const ExtStatusException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch ( const ExtRemoteException &Ex ) {
        err << wa::showminus << __FUNCTION__ << ": " << Ex.GetMessage() << endlerr;
    }
    catch( const ExtInterruptException& ) {
        throw;
    }

    display->PrintFooter();
}

void DisplayOneGDTEntry(const std::string &gdt_entry_name,
                        const unsigned __int64 entry_address,
                        const unsigned __int32 gdt_entry_size,
                        const unsigned __int32 gdt_selector,
                        const unsigned __int32 cpu_idx,
                        const unsigned __int64 kpcr_offset,
                        std::unique_ptr<WDbgArkAnalyzeBase> const &display) {
    std::stringstream processor_index;
    std::stringstream info;

    ExtRemoteTyped gdt_entry(gdt_entry_name.c_str(),
                             entry_address,
                             false,
                             NULL,
                             NULL);

    if ( g_Ext->IsCurMachine64() ) {
        info << std::setw(56);
        info << "<exec cmd=\"dx -r2 *(nt!_KGDTENTRY64 *)" << std::hex << std::showbase << gdt_entry.m_Offset;
        info << "\">dx" << "</exec>" << " ";
    } else {
        info << std::setw(54);
        info << "<exec cmd=\"dx -r3 *(nt!_KGDTENTRY *)" << std::hex << std::showbase << gdt_entry.m_Offset;
        info << "\">dx" << "</exec>" << " ";
    }

    info << "<exec cmd=\"dx -r1 *(nt!_KPCR *)" << std::hex << std::showbase << kpcr_offset;
    info << "\">pcr" << "</exec>" << " ";

    processor_index << std::setw(2) << cpu_idx << " / " << std::setw(2);
    processor_index << std::hex << gdt_selector / gdt_entry_size;

    display->Analyze(gdt_entry, processor_index.str(), gdt_selector, info.str());
    display->PrintFooter();
}

}   // namespace wa
