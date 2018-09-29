/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

nullFilter.c

Abstract:

This is the main module of the nullFilter mini filter driver.
It is a simple minifilter that registers itself with the main filter
for no callback operations.

Environment:

Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "driver.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------

#define TEF_FILTER_NAME     L"TransparentExtensionFilter"

typedef struct _TEF_CONTEXT_DATA {

	//
	//  The filter handle that results from a call to
	//  FltRegisterFilter.
	//

	PFLT_FILTER FilterHandle;

} TEF_CONTEXT_DATA, *PTEF_CONTEXT_DATA;


/*************************************************************************
Prototypes for the startup and unload routines used for
this Filter.

Implementation in nullFilter.c
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
TEFUnload (
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
TEFQueryTeardown (
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
TEFPreCallbackGeneral (
	_In_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
TEFPreCallbackGeneralNoPostOperation (
	_In_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
TEFPostCallbackGeneral (
	_In_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//
//  Structure that contains all the global data structures
//  used throughout NullFilter.
//

TEF_CONTEXT_DATA g_TEFContext;

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_CREATE_NAMED_PIPE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_CLOSE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_READ,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_WRITE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_QUERY_INFORMATION,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_SET_INFORMATION,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_QUERY_EA,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_SET_EA,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_FLUSH_BUFFERS,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_SET_VOLUME_INFORMATION,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_DIRECTORY_CONTROL,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_FILE_SYSTEM_CONTROL,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_DEVICE_CONTROL,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_INTERNAL_DEVICE_CONTROL,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_SHUTDOWN,
	0,
	TEFPreCallbackGeneralNoPostOperation,
	NULL },                               //post operations not supported

	{ IRP_MJ_LOCK_CONTROL,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_CLEANUP,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_CREATE_MAILSLOT,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_QUERY_SECURITY,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_SET_SECURITY,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_QUERY_QUOTA,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_SET_QUOTA,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_PNP,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_NETWORK_QUERY_OPEN,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_MDL_READ,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_MDL_READ_COMPLETE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_PREPARE_MDL_WRITE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_MDL_WRITE_COMPLETE,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_VOLUME_MOUNT,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_VOLUME_DISMOUNT,
	0,
	TEFPreCallbackGeneral,
	TEFPostCallbackGeneral },

	{ IRP_MJ_OPERATION_END }
};



//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, NullUnload)
#pragma alloc_text(PAGE, NullQueryTeardown)
#endif


//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                               //  Operation callbacks

	TEFUnload,                         //  FilterUnload

	NULL,                               //  InstanceSetup
	TEFQueryTeardown,                  //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

/*************************************************************************
Filter initialization and unload routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS TEFPreCallbackGeneral(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID * CompletionContext)
{
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS TEFPreCallbackGeneralNoPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID * CompletionContext)
{
	return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS  TEFPostCallbackGeneral(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	return STATUS_SUCCESS;
}

NTSTATUS
TEFQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This is the instance detach routine for this miniFilter driver.
This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach thereby giving us a
chance to fail that detach request.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Indicating where this detach request came from.

Return Value:

Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	return STATUS_SUCCESS;
}

/*
#############################################
########################################
	DriverEntry and DriverUnload
########################################
#############################################
*/


NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

This is the initialization routine for this miniFilter driver. This
registers the miniFilter with FltMgr and initializes all
its global data structures.

Arguments:

DriverObject - Pointer to driver object created by the system to
represent this driver.
RegistryPath - Unicode string identifying where the parameters for this
driver are located in the registry.

Return Value:

Returns STATUS_SUCCESS.

--*/
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	//
	//  Register with FltMgr
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&g_TEFContext.FilterHandle);

	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status)) {

		//
		//  Start filtering i/o
		//

		status = FltStartFiltering(g_TEFContext.FilterHandle);

		if (!NT_SUCCESS(status)) {
			FltUnregisterFilter(g_TEFContext.FilterHandle);
		}
	}
	return status;
}

NTSTATUS
TEFUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

This is the unload routine for this miniFilter driver. This is called
when the minifilter is about to be unloaded. We can fail this unload
request if this is not a mandatory unloaded indicated by the Flags
parameter.

Arguments:

Flags - Indicating if this is a mandatory unload.

Return Value:

Returns the final status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	FltUnregisterFilter(g_TEFContext.FilterHandle);

	return STATUS_SUCCESS;
}