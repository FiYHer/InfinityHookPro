#pragma once
#include "headers.hpp"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct _SYSTEM_MODULE
	{
		ULONG_PTR Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG_PTR ulModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	NTSTATUS ZwQuerySystemInformation(
		DWORD32 systemInformationClass,
		PVOID systemInformation,
		ULONG systemInformationLength,
		PULONG returnLength);

	NTSTATUS
		NTAPI
		NtTraceControl(
			_In_ ULONG FunctionCode,
			_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
			_In_ ULONG InBufferLen,
			_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
			_In_ ULONG OutBufferLen,
			_Out_ PULONG ReturnLength);

#ifdef __cplusplus
}
#endif