/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#pragma once
#include <Windows.h>
#include <iostream>
#include <stdint.h>
#include <cstdint>
#include <ctime>
#include <vector>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <mutex>
#include <map>
#include <stdio.h>
#include <wchar.h>
#include "Zydis/include/Zydis/Zydis.h"
#include "Keystone/include/keystone/keystone.h"

#define MAX_HOOKS 0x90000

// Errors
enum CH_Error_Info
{
	FALIED_NEEDS_INITIALIZATION = 40,
	FALIED_ALREADY_INITIALIZED,
	FALIED_HOOK_EXISTS,
	FALIED_HOOK_NOT_EXISTS,
	FALIED_BUFFER_CREATION,
	FALIED_INVALID_PARAMETER,
	FALIED_ALREADY_EXISTS,
	FALIED_NOT_EXISTS,
	FALIED_FREE_MEMORY,
	FALIED_UNHOOK,
	FALIED_HOOK,
	FALIED_NOT_ALLOWED,
	FALIED_NOT_HOOKED,
	FALIED_ALLOCATION,
	FALIED_NO_ACCESS,
	FALIED_DISASSEMBLER,
	FALIED_MEM_PROTECTION,
	FALIED_MODULE_NOT_FOUND,
	FALIED_FUNCTION_NOT_FOUND,
	FALIED_OUT_RANGE,
	FALIED_KEYSTONE_INIT,

	WARN_32_BIT
};

struct Hook_Info
{
	Hook_Info() : StatusHooked(false),
		Trampoline(false),
		OriginalF(NULL),
		HFunction(NULL),
		TrampolinePage(NULL),
		OrgData(NULL),
		HookData(NULL),
		HookSize(NULL),
		TrampolineSize(NULL),
		ModuleName(""),
		FunctionName("") {}

	bool StatusHooked;
	bool Trampoline;

	void* OriginalF;
	void* HFunction;
	void* TrampolinePage;

	void* OrgData;
	void* HookData;

	size_t HookSize;
	size_t TrampolineSize;
	
	// Optional members
	std::string ModuleName;
	std::string FunctionName;
};

namespace ColdHook_Service
{
	// Private functions:
	static bool IsAssemblerNeeded(const char* Instruction);

	//  Disassembler call
	static unsigned int DisasmRange(SIZE_T* OutPutInstructionsSize, ULONG_PTR* OutNextInst, SIZE_T HookSize, ULONG_PTR BaseAddressFormat, void* Buffer, void* TrampolineBuffer);

	// Generate base address
	static void* AllocateTrampoline(ULONG_PTR StartBaseAddress, SIZE_T PageS, int32_t* OutErrorCode, SIZE_T* ChangedHookSize);

	// Custom 
	static bool IsAddressRegisteredAsHook(void* Address);


	// Function wrap hooks
	int32_t InitFunctionHookByName(Hook_Info* OutputInfo, bool WrapFunction, bool CheckKBase, const char* ModulName, const char* FName, void* HookedF, int32_t* OutErrorCode);
	int32_t InitFunctionHookByAddress(Hook_Info* OutputInfo, bool WrapFunction, void* Target, void* HookedF, int32_t* OutErrorCode);

	// Memory custom hook
	int32_t InitHookCustomData(Hook_Info* OutputInfo, void* Target, void* CustomData, size_t CSize, int32_t* OutErrorCode);

	// UnHook
	bool UnHookRegisteredData(int32_t HookID, int32_t* OutErrorCode);
	bool HookAgainRegisteredData(int32_t HookID, int32_t* OutErrorCode);

	// Init And shut down
	bool ServiceGlobalInit(int32_t* OutErrorCode);
	bool ServiceGlobalShutDown(int32_t* OutErrorCode);

	// Informations
	bool RetrieveHookInfoByID(Hook_Info* OutputInfo, int32_t HookID, int32_t* OutErrorCode);
	bool RetrieveHookIDByInfo(Hook_Info* InputInfo, int32_t* OutHookID, int32_t* OutErrorCode);

	bool ServiceRegisterHookInformation(Hook_Info* InputInfo, int32_t HookID, int32_t* OutErrorCode);
	bool ServiceUnRegisterHookInformation(int32_t HookID, int32_t* OutErrorCode);

	// Arch
	bool Is64BitProcess();

	// Error handler 
	const char* CHRetrieveErrorCodeString(int32_t InErrorCode);
}