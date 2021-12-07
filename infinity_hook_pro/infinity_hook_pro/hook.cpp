#include "hook.hpp"
#include "utils.hpp"

#pragma warning(disable : 4201)

/* 微软官方文档定义
*   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header*/
typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

/* 微软文档定义
*   https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties*/
typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

/* 这结构是大佬逆向出来的 */
typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64 Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

// 操作类型
typedef enum _trace_type
{
	start_trace = 1,
	stop_trace = 2,
	query_trace = 3,
	syscall_trace = 4,
	flush_trace = 5
}trace_type;

namespace k_hook
{
	// 这个值是固定不变的
	GUID g_ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

	fptr_call_back g_fptr = nullptr;
	unsigned long g_build_number = 0;

	void* g_EtwpDebuggerData = nullptr;
	void* g_CkclWmiLoggerContext = nullptr;
	void* g_syscall_table = nullptr;

	void** g_EtwpDebuggerDataSilo = nullptr;
	void** g_GetCpuClock = nullptr;

	unsigned long long h_original_GetCpuClock = 0;
	unsigned long long g_HvlpReferenceTscPage = 0;
	unsigned long long g_HvlGetQpcBias = 0;
	typedef __int64 (*fptr_HvlGetQpcBias)();
	fptr_HvlGetQpcBias g_original_HvlGetQpcBias = nullptr;

	// 修改跟踪设置
	NTSTATUS modify_trace_settings(trace_type type)
	{
		const unsigned long tag = 'VMON';

		// 申请结构体空间
		CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, tag);
		if (!property)
		{
			DbgPrintEx(0, 0, "[%s] allocate ckcl trace propertice struct fail \n", __FUNCTION__);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		// 申请保存名称的空间
		wchar_t* provider_name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(wchar_t), tag);
		if (!provider_name)
		{
			DbgPrintEx(0, 0, "[%s] allocate provider name fail \n", __FUNCTION__);
			ExFreePoolWithTag(property, tag);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		// 清空内存
		RtlZeroMemory(property, PAGE_SIZE);
		RtlZeroMemory(provider_name, 256 * sizeof(wchar_t));

		// 名称赋值
		RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
		RtlInitUnicodeString(&property->ProviderName, (const wchar_t*)provider_name);

		// 结构体填充
		property->Wnode.BufferSize = PAGE_SIZE;
		property->Wnode.Flags = 0x00020000;
		property->Wnode.Guid = g_ckcl_session_guid;
		property->Wnode.ClientContext = 3;
		property->BufferSize = sizeof(unsigned long);
		property->MinimumBuffers = 2;
		property->MaximumBuffers = 2;
		property->LogFileMode = 0x00000400;

		// 执行操作
		unsigned long length = 0;
		if (type == trace_type::syscall_trace) property->EnableFlags = 0x00000080;
		NTSTATUS status = NtTraceControl(type, property, PAGE_SIZE, property, PAGE_SIZE, &length);

		// 释放内存空间
		ExFreePoolWithTag(provider_name, tag);
		ExFreePoolWithTag(property, tag);

		return status;
	}

	// 我们的替换函数,针对的是从Win7到Win10 1909的系统
	unsigned long long self_get_cpu_clock()
	{
		// 放过内核模式的调用
		if (ExGetPreviousMode() == KernelMode) return __rdtsc();

		// 拿到当前线程
		PKTHREAD current_thread = (PKTHREAD)__readgsqword(0x188);

		// 不同版本不同偏移
		unsigned int call_index = 0;
		if (g_build_number <= 7601) call_index = *(unsigned int*)((unsigned long long)current_thread + 0x1f8);
		else call_index = *(unsigned int*)((unsigned long long)current_thread + 0x80);

		// 拿到当前栈底和栈顶
		void** stack_max = (void**)__readgsqword(0x1a8);
		void** stack_frame = (void**)_AddressOfReturnAddress();

		// 开始查找当前栈中的ssdt调用
		for (void** stack_current = stack_max; stack_current > stack_frame; --stack_current)
		{
			/* 栈中ssdt调用特征,分别是
			*   mov [rsp+48h+var_20], 501802h
			*   mov r9d, 0F33h
			*/
#define INFINITYHOOK_MAGIC_1 ((unsigned long)0x501802)
#define INFINITYHOOK_MAGIC_2 ((unsigned short)0xF33)

			// 第一个特征值检查
			unsigned long* l_value = (unsigned long*)stack_current;
			if (*l_value != INFINITYHOOK_MAGIC_1) continue;

			// 这里为什么减?配合寻找第二个特征值啊
			--stack_current;

			// 第二个特征值检查
			unsigned short* s_value = (unsigned short*)stack_current;
			if (*s_value != INFINITYHOOK_MAGIC_2) continue;

			// 特征值匹配成功,再倒过来查找
			for (; stack_current < stack_max; ++stack_current)
			{
				// 检查是否在ssdt表内
				unsigned long long* ull_value = (unsigned long long*)stack_current;
				if (!(PAGE_ALIGN(*ull_value) >= g_syscall_table && PAGE_ALIGN(*ull_value) < (void*)((unsigned long long)g_syscall_table + (PAGE_SIZE * 2)))) continue;

				// 现在已经确定是ssdt函数调用了
				// 这里是找到KiSystemServiceExit
				void** system_call_function = &stack_current[9];

				// 调用回调函数
				if (g_fptr) g_fptr(call_index, system_call_function);

				// 跳出循环
				break;
			}

			// 跳出循环
			break;
		}

		// 调用原函数
		return __rdtsc();
	}

	// 我们的替换函数,针对的是Win 1919往上的系统
	EXTERN_C __int64 self_hvl_get_qpc_bias()
	{
		// 我们的过滤函数
		self_get_cpu_clock();

		// 这里是真正HvlGetQpcBias做的事情
		return *((unsigned long long*)(*((unsigned long long*)g_HvlpReferenceTscPage)) + 3);
	}

	bool initialize(fptr_call_back fptr)
	{
		// 回调函数指针检查
		if (!fptr) return false;
		DbgPrintEx(0, 0, "[%s] call back ptr is 0x%p \n", __FUNCTION__, fptr);
		g_fptr = fptr;

		// 获取系统版本号
		g_build_number = k_utils::get_system_build_number();
		if (!g_build_number) return false;
		DbgPrintEx(0, 0, "[%s] build number is %ld \n", __FUNCTION__, g_build_number);

		// 获取系统基址
		unsigned long long ntoskrnl = k_utils::get_module_address("ntoskrnl.exe", nullptr);
		if (!ntoskrnl) return false;
		DbgPrintEx(0, 0, "[%s] ntoskrnl address is 0x%llX \n", __FUNCTION__, ntoskrnl);

		// 这里不同系统不同位置
		unsigned long long EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
		if (!EtwpDebuggerData) return false;
		DbgPrintEx(0, 0, "[%s] etwp debugger data is 0x%llX \n", __FUNCTION__, EtwpDebuggerData);
		g_EtwpDebuggerData = (void*)EtwpDebuggerData;

		// 这里暂时不知道怎么定位,偏移0x10在全部系统都一样
		g_EtwpDebuggerDataSilo = *(void***)((unsigned long long)g_EtwpDebuggerData + 0x10);
		if (!g_EtwpDebuggerDataSilo) return false;
		DbgPrintEx(0, 0, "[%s] etwp debugger data silo is 0x%p \n", __FUNCTION__, g_EtwpDebuggerDataSilo);

		// 这里也不知道怎么定位,偏移0x2在全部系统都哦一样
		g_CkclWmiLoggerContext = g_EtwpDebuggerDataSilo[0x2];
		if (!g_CkclWmiLoggerContext) return false;
		DbgPrintEx(0, 0, "[%s] ckcl wmi logger context is 0x%p \n", __FUNCTION__, g_CkclWmiLoggerContext);

		/*  改值会改变两次 ? 会变成无效指针一次 ? 以前好像有过类似的经历
		*   靠,Win11的偏移变成了0x18,看漏的害我调试这么久  -_-
		*   这里总结一下,Win7和Win11都是偏移0x18,其它的是0x28
		*/
		if (g_build_number <= 7601 || g_build_number == 22000) g_GetCpuClock = (void**)((unsigned long long)g_CkclWmiLoggerContext + 0x18); // Win7版本以及更旧, Win11也是
		else g_GetCpuClock = (void**)((unsigned long long)g_CkclWmiLoggerContext + 0x28); // Win8 -> Win10全系统
		if (!MmIsAddressValid(g_GetCpuClock)) return false;
		DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p \n", __FUNCTION__, *g_GetCpuClock);

		// 拿到ssdt指针
		g_syscall_table = PAGE_ALIGN(k_utils::get_syscall_entry(ntoskrnl));
		if (!g_syscall_table) return false;
		DbgPrintEx(0, 0, "[%s] syscall table is 0x%p \n", __FUNCTION__, g_syscall_table);

		if (g_build_number > 18363)
		{
			/* HvlGetQpcBias函数内部需要用到这个结构
			*   所以我们手动定位这个结构
			*/
			unsigned long long address = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
				"xxx????xxx?xxx????xxx");
			if (!address) return false;
			g_HvlpReferenceTscPage = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 3));
			if (!g_HvlpReferenceTscPage) return false;
			DbgPrintEx(0, 0, "[%s] hvlp reference tsc page is 0x%llX \n", __FUNCTION__, g_HvlpReferenceTscPage);

			/* 这里我们查找到HvlGetQpcBias的指针
			*   详细介绍可以看https://www.freebuf.com/articles/system/278857.html
			*/
			address = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74",
				"xxx????xxxx?xxx?????x");
			if (!address) return false;
			g_HvlGetQpcBias = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 3));
			if (!g_HvlGetQpcBias) return false;
			DbgPrintEx(0, 0, "[%s] hvl get qpc bias is 0x%llX \n", __FUNCTION__, g_HvlGetQpcBias);
		}

		return true;
	}

	bool start()
	{
		if (!g_fptr) return false;

		// 先尝试挂钩
		if (!NT_SUCCESS(modify_trace_settings(syscall_trace)))
		{
			// 无法开启CKCL
			if (!NT_SUCCESS(modify_trace_settings(start_trace)))
			{
				DbgPrintEx(0, 0, "[%s] start ckcl fail \n", __FUNCTION__);
				return false;
			}

			// 再次尝试挂钩
			if (!NT_SUCCESS(modify_trace_settings(syscall_trace)))
			{
				DbgPrintEx(0, 0, "[%s] syscall ckcl fail \n", __FUNCTION__);
				return false;
			}
		}

		// 无效指针
		if (!MmIsAddressValid(g_GetCpuClock))
		{
			DbgPrintEx(0, 0, "[%s] get cpu clock vaild \n", __FUNCTION__);
			return false;
		}

		/* 这里我们区分一下系统版本
		*   从Win7到Win10 1909,g_GetCpuClock是一个函数,往后的版本是一个数值了
		*   大于3抛异常
		*   等于3用rdtsc
		*   等于2用off_140C00A30
		*   等于1用KeQueryPerformanceCounter
		*   等于0用RtlGetSystemTimePrecise
		*   我们的做法参考网址https://www.freebuf.com/articles/system/278857.html
		*   我们这里在2身上做文章
		*/
		if (g_build_number <= 18363)
		{
			// 直接修改函数指针
			DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p\n", __FUNCTION__, *g_GetCpuClock);
			*g_GetCpuClock = self_get_cpu_clock;
			DbgPrintEx(0, 0, "[%s] update get cpu clock is 0x%p\n", __FUNCTION__, *g_GetCpuClock);
		}
		else
		{
			// 保存GetCpuClock原始值,退出时好恢复
			h_original_GetCpuClock = (unsigned long long)(*g_GetCpuClock);

			/* 这里我们设置为2, 这样子才能调用off_140C00A30函数
			*   其实该指针就是HalpTimerQueryHostPerformanceCounter函数
			*   该函数里面又有两个函数指针,第一个就是HvlGetQpcBias,就是我们的目标
			*/
			*g_GetCpuClock = (void*)2;
			DbgPrintEx(0, 0, "[%s] update get cpu clock is %p \n", __FUNCTION__, *g_GetCpuClock);

			// 保存旧HvlGetQpcBias地址,方便后面清理的时候复原环境
			g_original_HvlGetQpcBias = (fptr_HvlGetQpcBias)(*((unsigned long long*)g_HvlGetQpcBias));

			// 设置钩子
			*((unsigned long long*)g_HvlGetQpcBias) = (unsigned long long)self_hvl_get_qpc_bias;
			DbgPrintEx(0, 0, "[%s] update hvl get qpc bias is %p \n", __FUNCTION__, self_hvl_get_qpc_bias);
		}

		return true;
	}

	bool stop()
	{
		bool result = NT_SUCCESS(modify_trace_settings(stop_trace)) && NT_SUCCESS(modify_trace_settings(start_trace));

		// Win10 1909以上系统需要恢复环境
		if (g_build_number > 18363)
		{
			*((unsigned long long*)g_HvlGetQpcBias) = (unsigned long long)g_original_HvlGetQpcBias;
			*g_GetCpuClock = (void*)h_original_GetCpuClock;
		}

		return result;
	}
}
