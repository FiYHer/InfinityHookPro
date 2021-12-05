#pragma once
#include "imports.hpp"
#include "hde/hde64.h"

namespace k_utils
{
	// 获取系统版本号
	unsigned long get_system_build_number()
	{
		unsigned long number = 0;
		RTL_OSVERSIONINFOEXW info{ 0 };
		info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		if (NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&info))) number = info.dwBuildNumber;
		return number;
	}

	// 获取指定模块基址
	unsigned long long get_module_address(const char* name, unsigned long* size)
	{
		unsigned long long result = 0;

		unsigned long length = 0;
		ZwQuerySystemInformation(11, &length, 0, &length);
		if (!length) return result;

		const unsigned long tag = 'VMON';
		PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
		if (!system_modules) return result;

		NTSTATUS status = ZwQuerySystemInformation(11, system_modules, length, 0);
		if (NT_SUCCESS(status))
		{
			for (unsigned long long i = 0; i < system_modules->ulModuleCount; i++)
			{
				PSYSTEM_MODULE mod = &system_modules->Modules[i];
				if (strstr(mod->ImageName, name))
				{
					result = (unsigned long long)mod->Base;
					if (size) *size = (unsigned long)mod->Size;
					break;
				}
			}
		}

		ExFreePoolWithTag(system_modules, tag);
		return result;
	}

	// 模式匹配
	bool pattern_check(const char* data, const char* pattern, const char* mask)
	{
		size_t len = strlen(mask);

		for (size_t i = 0; i < len; i++)
		{
			if (data[i] == pattern[i] || mask[i] == '?')
				continue;
			else
				return false;
		}

		return true;
	}

	// 模式查找
	unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
	{
		size -= (unsigned long)strlen(mask);

		for (unsigned long i = 0; i < size; i++)
		{
			if (pattern_check((const char*)addr + i, pattern, mask))
				return addr + i;
		}

		return 0;
	}

	// 查找映像模式
	unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask, const char* name = ".text")
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &section[i];

			if (strstr((const char*)p->Name, name))
			{
				unsigned long long result = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
				if (result) return result;
			}
		}

		return 0;
	}

	// 获取映像地址
	unsigned long long get_image_address(unsigned long long addr, const char* name, unsigned long* size)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &section[i];

			if (strstr((const char*)p->Name, name))
			{
				if (size) *size = p->SizeOfRawData;
				return (unsigned long long)p + p->VirtualAddress;
			}
		}

		return 0;
	}

	// 获取SSDT表地址
	void* get_syscall_entry(unsigned long long ntoskrnl)
	{
		if (!ntoskrnl) return nullptr;

		/*
		2018年的内核页表隔离补丁 https://bbs.pediy.com/thread-223805.htm
		没有补丁的话就是KiSystemCall64
		*/
#define IA32_LSTAR_MSR 0xC0000082
		void* syscall_entry = (void*)__readmsr(IA32_LSTAR_MSR);

		// 没有补丁过,直接返回KiSystemCall64就行
		unsigned long section_size = 0;
		unsigned long long KVASCODE = get_image_address(ntoskrnl, "KVASCODE", &section_size);
		if (!KVASCODE) return syscall_entry;

		// KiSystemCall64还是在区域内,也是直接返回
		if (!(syscall_entry >= (void*)KVASCODE && syscall_entry < (void*)(KVASCODE + section_size))) return syscall_entry;

		// 来到这一步那就是KiSystemCall64Shadow,代表打补丁了
		hde64s hde_info{ 0 };
		for (char* ki_system_service_user = (char*)syscall_entry; ; ki_system_service_user += hde_info.len)
		{
			// 反汇编
			if (!hde64_disasm(ki_system_service_user, &hde_info)) break;

			// 我们要查找jmp
#define OPCODE_JMP_NEAR 0xE9
			if (hde_info.opcode != OPCODE_JMP_NEAR) continue;

			// 忽略在KVASCODE节区内的jmp指令
			void* possible_syscall_entry = (void*)((long long)ki_system_service_user + (int)hde_info.len + (int)hde_info.imm.imm32);
			if (possible_syscall_entry >= (void*)KVASCODE && possible_syscall_entry < (void*)((unsigned long long)KVASCODE + section_size)) continue;

			// 发现KiSystemServiceUser
			syscall_entry = possible_syscall_entry;
			break;
		}

		return syscall_entry;
	}
}