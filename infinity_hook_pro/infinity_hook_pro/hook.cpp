#include "hook.hpp"
#include "utils.hpp"

#pragma warning(disable : 4201 4819 4311 4302)

/* 微软官方文档定义
*   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header
*/
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
*   https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
*/
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

/* 
*  这结构是大佬逆向出来的 
*/
typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64 Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

/* 
*  操作类型
*/
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
	GUID m_ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } }; // 这个值是固定不变的

	fptr_call_back m_fptr = nullptr; // 回调函数指针
	unsigned long m_build_number = 0; // 系统版本号
	void* m_syscall_table = nullptr; // 系统调用表指针
	bool m_routine_status = true; // 检测线程的运行状态

	void* m_EtwpDebuggerData = nullptr; 
	void* m_CkclWmiLoggerContext = nullptr;
	
	void** m_EtwpDebuggerDataSilo = nullptr;
	void** m_GetCpuClock = nullptr;

	unsigned long long m_original_GetCpuClock = 0;
	unsigned long long m_HvlpReferenceTscPage = 0;
	unsigned long long m_HvlGetQpcBias = 0;

	typedef __int64 (*fptr_HvlGetQpcBias)();
	fptr_HvlGetQpcBias m_original_HvlGetQpcBias = nullptr;

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
		property->Wnode.Guid = m_ckcl_session_guid;
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
		if (m_build_number <= 7601) call_index = *(unsigned int*)((unsigned long long)current_thread + 0x1f8);
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
				if (!(PAGE_ALIGN(*ull_value) >= m_syscall_table && PAGE_ALIGN(*ull_value) < (void*)((unsigned long long)m_syscall_table + (PAGE_SIZE * 2)))) continue;

				// 现在已经确定是ssdt函数调用了
				// 这里是找到KiSystemServiceExit
				void** system_call_function = &stack_current[9];

				// 调用回调函数
				if (m_fptr) m_fptr(call_index, system_call_function);

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
		return *((unsigned long long*)(*((unsigned long long*)m_HvlpReferenceTscPage)) + 3);
	}

	// 检测例程
	void detect_routine(void*)
	{
		while (m_routine_status)
		{
			// 线程常用休眠
			k_utils::sleep(5000);

			// 保存原始的GetCpuClock值,看清楚这里是静态变量
			static void* GetCpuClockValue = 0;
			if (MmIsAddressValid(m_GetCpuClock) && MmIsAddressValid(*m_GetCpuClock))
			{
				/*
				* 在Win7系统上,GetCpuClock值会发生改变,会变成无效值,持续时间不确定但是很短
				* 然后GetCpuClock值恢复后会变成一个新的有效值,但不是原来我们设置的那个
				*/

				// 静态变量首次赋值
				if (GetCpuClockValue == 0) GetCpuClockValue = *m_GetCpuClock;

				// 值不一样,必须重新挂钩
				if (GetCpuClockValue != *m_GetCpuClock)
				{
					// 更新GetCpuClock值
					GetCpuClockValue = *m_GetCpuClock;

					// GetCpuClock值有效后,再次挂钩一般执行结果都是成功的
					if (initialize(m_fptr))
						if (start())
							PsTerminateSystemThread(0);
				}
			}
			else initialize(m_fptr); // GetCpuClock无效后要重新获取
		}
	}

	bool initialize(fptr_call_back fptr)
	{
		// 回调函数指针检查
		DbgPrintEx(0, 0, "[%s] call back ptr is 0x%p \n", __FUNCTION__, fptr);
		if (!fptr) return false;
		else m_fptr = fptr;

		// 获取系统版本号
		m_build_number = k_utils::get_system_build_number();
		DbgPrintEx(0, 0, "[%s] build number is %ld \n", __FUNCTION__, m_build_number);
		if (!m_build_number) return false;

		// 获取系统基址
		unsigned long long ntoskrnl = k_utils::get_module_address("ntoskrnl.exe", nullptr);
		DbgPrintEx(0, 0, "[%s] ntoskrnl address is 0x%llX \n", __FUNCTION__, ntoskrnl);
		if (!ntoskrnl) return false;

		// 这里不同系统不同位置
		// https://github.com/FiYHer/InfinityHookPro/issues/17  win10 21h2.2130 安装 KB5018410 补丁后需要使用新的特征码 
		unsigned long long EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
		DbgPrintEx(0, 0, "[%s] etwp debugger data is 0x%llX \n", __FUNCTION__, EtwpDebuggerData);
		if (!EtwpDebuggerData) return false;
		m_EtwpDebuggerData = (void*)EtwpDebuggerData;

		// 这里暂时不知道怎么定位,偏移0x10在全部系统都一样
		m_EtwpDebuggerDataSilo = *(void***)((unsigned long long)m_EtwpDebuggerData + 0x10);
		DbgPrintEx(0, 0, "[%s] etwp debugger data silo is 0x%p \n", __FUNCTION__, m_EtwpDebuggerDataSilo);
		if (!m_EtwpDebuggerDataSilo) return false;

		// 这里也不知道怎么定位,偏移0x2在全部系统都哦一样
		m_CkclWmiLoggerContext = m_EtwpDebuggerDataSilo[0x2];
		DbgPrintEx(0, 0, "[%s] ckcl wmi logger context is 0x%p \n", __FUNCTION__, m_CkclWmiLoggerContext);
		if (!m_CkclWmiLoggerContext) return false;

		/*  Win7系统测试,m_GetCpuClock该值会改变几次,先阶段使用线程检测后修复
		*   靠,Win11的偏移变成了0x18,看漏的害我调试这么久  -_-
		*   这里总结一下,Win7和Win11都是偏移0x18,其它的是0x28
		*/
		if (m_build_number <= 7601 || m_build_number >= 22000) m_GetCpuClock = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x18); // Win7版本以及更旧, Win11也是
		else m_GetCpuClock = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x28); // Win8 -> Win10全系统
		if (!MmIsAddressValid(m_GetCpuClock)) return false;
		DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p \n", __FUNCTION__, *m_GetCpuClock);

		// 拿到ssdt指针
		m_syscall_table = PAGE_ALIGN(k_utils::get_syscall_entry(ntoskrnl));
		DbgPrintEx(0, 0, "[%s] syscall table is 0x%p \n", __FUNCTION__, m_syscall_table);
		if (!m_syscall_table) return false;

		if (m_build_number > 18363)
		{
			/* HvlGetQpcBias函数内部需要用到这个结构
			*   所以我们手动定位这个结构
			*/
			unsigned long long address = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
				"xxx????xxx?xxx????xxx");
			if (!address) return false;
			m_HvlpReferenceTscPage = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 3));
			DbgPrintEx(0, 0, "[%s] hvlp reference tsc page is 0x%llX \n", __FUNCTION__, m_HvlpReferenceTscPage);
			if (!m_HvlpReferenceTscPage) return false;

			/* 这里我们查找到HvlGetQpcBias的指针
			*   详细介绍可以看https://www.freebuf.com/articles/system/278857.html
			*/
			address = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74",
				"xxx????xxxx?xxx?????x");
			if (!address) return false;
			m_HvlGetQpcBias = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 3));
			DbgPrintEx(0, 0, "[%s] hvl get qpc bias is 0x%llX \n", __FUNCTION__, m_HvlGetQpcBias);
			if (!m_HvlGetQpcBias) return false;
		}

		return true;
	}

	bool start()
	{
		if (!m_fptr) return false;

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
		if (!MmIsAddressValid(m_GetCpuClock))
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
		if (m_build_number <= 18363)
		{
			// 直接修改函数指针
			DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p\n", __FUNCTION__, *m_GetCpuClock);
			*m_GetCpuClock = self_get_cpu_clock;
			DbgPrintEx(0, 0, "[%s] update get cpu clock is 0x%p\n", __FUNCTION__, *m_GetCpuClock);
		}
		else
		{
			// 保存GetCpuClock原始值,退出时好恢复
			m_original_GetCpuClock = (unsigned long long)(*m_GetCpuClock);

			/* 这里我们设置为2, 这样子才能调用off_140C00A30函数
			*   其实该指针就是HalpTimerQueryHostPerformanceCounter函数
			*   该函数里面又有两个函数指针,第一个就是HvlGetQpcBias,就是我们的目标
			*/
			*m_GetCpuClock = (void*)2;
			DbgPrintEx(0, 0, "[%s] update get cpu clock is %p \n", __FUNCTION__, *m_GetCpuClock);

			// 保存旧HvlGetQpcBias地址,方便后面清理的时候复原环境
			m_original_HvlGetQpcBias = (fptr_HvlGetQpcBias)(*((unsigned long long*)m_HvlGetQpcBias));

			// 设置钩子
			*((unsigned long long*)m_HvlGetQpcBias) = (unsigned long long)self_hvl_get_qpc_bias;
			DbgPrintEx(0, 0, "[%s] update hvl get qpc bias is %p \n", __FUNCTION__, self_hvl_get_qpc_bias);
		}

		// 创建GetCpuClock数值检测线程
		HANDLE h_thread = NULL;
		CLIENT_ID client{ 0 };
		OBJECT_ATTRIBUTES att{ 0 };
		InitializeObjectAttributes(&att, 0, OBJ_KERNEL_HANDLE, 0, 0);
		NTSTATUS status = PsCreateSystemThread(&h_thread, THREAD_ALL_ACCESS, &att, 0, &client, detect_routine, 0);
		if (NT_SUCCESS(status)) ZwClose(h_thread);
		DbgPrintEx(0, 0, "[%s] detect routine thread id is %d \n", __FUNCTION__, (int)client.UniqueThread);

		return true;
	}

	bool stop()
	{
		// 停止检测线程
		m_routine_status = false;

		bool result = NT_SUCCESS(modify_trace_settings(stop_trace)) && NT_SUCCESS(modify_trace_settings(start_trace));

		// Win10 1909以上系统需要恢复环境
		if (m_build_number > 18363)
		{
			*((unsigned long long*)m_HvlGetQpcBias) = (unsigned long long)m_original_HvlGetQpcBias;
			*m_GetCpuClock = (void*)m_original_GetCpuClock;
		}

		return result;
	}
}
