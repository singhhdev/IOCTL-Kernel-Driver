#pragma once
#pragma warning (disable: 4100)

typedef struct __readRequests
{
	int SourceProcessID; // source PID
	uint64_t SourceAddress; // where to read from
	uint64_t ReturnAddress; // what to return to user
	size_t Size; //size of the buffer

} read, * readRequest;

typedef struct __writeRequests
{
	int SourceProcessID; // source of where to write to 
	uint64_t SourceAddress; // source to where write
	uint64_t ReturnAddress; // what to write
	size_t Size; // size

} write, * writeRequest; 

typedef struct __base
{
	int TargetProcessID;		//target process 
	uint64_t ReturnAddress; // the baseaddress it gest
	uint64_t GuardedRegion; // the GR

} baseAddress, * baseRequest;

typedef struct __guardedRegion
{
	uint64_t GuardedRegion;

} guardedRegion, * guardedRequest;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool.htm
typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	system_basic_information,
	system_processor_information,
	system_performance_information,
	system_time_of_day_information,
	system_path_information,
	system_process_information,
	system_call_count_information,
	system_device_information,
	system_processor_performance_information,
	system_flags_information,
	system_call_time_information,
	system_module_information,
	system_locks_information,
	system_stack_trace_information,
	system_paged_pool_information,
	system_non_paged_pool_information,
	system_handle_information,
	system_object_information,
	system_page_file_information,
	system_vdm_instemul_information,
	system_vdm_bop_information,
	system_file_cache_information,
	system_pool_tag_information,
	system_interrupt_information,
	system_dpc_behavior_information,
	system_full_memory_information,
	system_load_gdi_driver_information,
	system_unload_gdi_driver_information,
	system_time_adjustment_information,
	system_summary_memory_information,
	system_next_event_id_information,
	system_event_ids_information,
	system_crash_dump_information,
	system_exception_information,
	system_crash_dump_state_information,
	system_kernel_debugger_information,
	system_context_switch_information,
	system_registry_quota_information,
	system_extend_service_table_information,
	system_priority_seperation,
	system_plug_play_bus_information,
	system_dock_information,
	system_processor_speed_information,
	system_current_time_zone_information,
	system_lookaside_information,
	system_bigpool_information = 0x42
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;