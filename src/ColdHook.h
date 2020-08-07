/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#pragma once
#include <Windows.h>
#include <tlhelp32.h>

// standard libraries
#include <stdint.h>
#include <chrono>
#include <map>
#include <mutex>

// additional
#include "Zydis/include/Zydis/Zydis.h"

#define OFFSET_JUMP_LONG_AND_OFFSET_CALL 5
#define OFFSET_JUMP_COND_SHORT 2
#define OFFSET_JUMP_LONG_HOOK_SIZE OFFSET_JUMP_LONG_AND_OFFSET_CALL
#define OFFSET_JUMP_SHORT_HOOK_SIZE OFFSET_JUMP_COND_SHORT
#define DISPLACEMENT_OFFSET 1
#define ABS_CALL_AND_COND_OFFSET_LONG_JUMP 6

#define RANDOM_ALLOCATED_64 3
#define RANDOM_ALLOCATED_32 1
#define ALLOCATED_64_2GB_CLOSE 2

#ifndef _WIN64
#define ABS_HOOK_SIZE 10
#define MAX_CAVE_DATA (OFFSET_JUMP_LONG_AND_OFFSET_CALL + 20)
#else
#define ABS_HOOK_SIZE 14
#define MAX_CAVE_DATA ((ABS_HOOK_SIZE * 2) + 20)
#endif
#define ABS_JUMP_ADDRESS_OFFSET 6
#define ABS_64_HOOK_SIZE 14

#define POSITIVE 1
#define NEGATIVE 2
#define EQUAL 3

#define MAX_HOOK_ARRAY 16
#define MAX_COND_SHORT_JUMP_OFFSET_P 0x81
#define MAX_COND_SHORT_JUMP_OFFSET_N 0x7E
#define MAX_HOOKS 0x90000
#define MAX_TRAMPSIZE 0x1000
#define MAX_RANGE_DELTA_P 2147483648
#define MAX_RANGE_DELTA_N -2147483648
#define MAX_INSTRUCTIONS 40

enum InstructionType
{
	T_GENERAL_UNKNOWN,
	TSPECIAL__GENERAL_JUMP_C,
	TCONDITIONAL_GENERAL_JUMP,
	TOFFSET_GENERAL_JUMP,
	TOFFSET_GENERAL_CALL,
	TABSOLUTE_GENERAL_CALL,
	TABSOLUTE_GENERAL_JUMP,
	TABSOLUTE_GENERAL_JUMP_CUSTOM
};
enum OffsetTypes
{
	TUNKNOWN,
	TSPECIAL_JUMP_C,
	TCONDITIONAL_LONG_JUMP,
	TCONDITIONAL_SHORT_JUMP,
	TOFFSET_SHORT_JUMP,
	TOFFSET_LONG_JUMP,
	TOFFSET_CALL,
	TABSOLUTE_CALL,
	TABSOLUTE_JUMP,
	TABSOLUTE_JUMP_CUSTOM
};

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
	FALIED_TRAMPOLINE_NOT_FOUND,
	FALIED_HOOK_STILL_EXISTS_ACCESS_DENIED,
	FALIED_CUSTOM_ORIGINAL_BUFFER_NOT_FOUND
};

struct Hook_Info
{
	bool StatusHooked;
	bool TrampolineAllocated;
	bool IsDetourHook;

	void* OriginalF;	// Pointer to the original function 
	void* HFunction;	// Target hooked/hook pointer 
	void* TrampolinePage;	// Trampoline address 
	void* COrgData;
	void* CHookData;

	BYTE OrgData[MAX_HOOK_ARRAY];	// original data (for detour)
	BYTE HookData[MAX_HOOK_ARRAY];	// hook data	(for detour)
	BYTE CaveHookData[MAX_CAVE_DATA];
	BYTE CodeCaveOData;

	DWORD CaveOriginalProtection;
	size_t HookSize;
};

namespace ColdHook_Service
{
	// Private functions:
	static void* WalkThroughJumpIfPossible(void* pMemory);
	static void* GetAddressFromOffset(void* Base, OffsetTypes Type, size_t DispOffset, size_t InsLength, bool bReturnDefault, bool bGetInternalP);
	static void* BeckupOriginalInstructions(void* pTarget, void* pTrampolineStart, size_t JumpHookS, size_t* pOutDLength);
	static void* FindTrampoline(void* StartBaseAddress, size_t Size, bool UseCodeCave, int* pAllocated, DWORD* pCaveOProtection);

	static size_t FixInstruction(void* pTarget, void* pNewPointer, bool bIsRelative, int DispValue, size_t CurrentInsLength);
	static size_t GetDisplacementOffset(void* pInstruction, int DisplaceMent, size_t InsLength, bool* pbFalied);
	static size_t PlaceOffsetJump(void* pDestination, void* pTarget, void* pMemory);
	static size_t PlaceAbsJump(void* pDestination, void* pMemory);
	static WORD ConvertOpcode(void* pInstruction, InstructionType InsType, bool bToLong);

	static int BuildInstructionTypeDisplaceMent(void* pDestination, void* pTarget, InstructionType InsType, size_t* pNeededEncodeLength,
		size_t* pNewDisplaceMentOffset, size_t InsLength, bool* pbLongJump, bool* pbFalied);

	static InstructionType GetInstructionTypeFromOffsetType(OffsetTypes OffType);
	static OffsetTypes GetInstructionOffType(void* pInstruction);
	
	static bool MustInstructionBeFixed(OffsetTypes Type, bool bLongDistance);
	static bool IsValidMem(void* pMem, bool bWriteAccessNeeded);
	static bool EncodeDisplaceMentInstruction(void* pMemory, void* pOldOpCode, int offset, InstructionType InsType, bool bConvertOpcode,
		bool IsLong, size_t EncodeSize, size_t DispOffset);
	static bool SearchAddressThroughSecs(void* ModBase, void* CurAddr, void** OutSBaseAddr, size_t* pSize);
	static bool IsValidHeader(void* CurrentBase);
	static bool IsHookAlreadyRegistered(int32_t HookID);

	static void LockOrUnlockOtherThreads(bool bLock);

	static Hook_Info* InternalInitializeSTR(bool bDetourHook);
	static void InternalUnHookRegData(bool ShutDown, Hook_Info* pData, int32_t* OutErrorCode);
	static void InternalHookRegData(Hook_Info* pData, int32_t* OutErrorCode);
	static void InternalEmuHook(void* pPlace, void* pDFunction, Hook_Info* OutputInfo, int32_t* pOutErrorCode);
	static void* InternalDetourHook(void* pPlace, void* pDFunction, Hook_Info* OutputInfo, int32_t* pOutErrorCode);

	// Function wrap hooks
	int32_t InitFunctionHookByName(Hook_Info** OutputInfo, bool WrapFunction, bool CheckKBase, const char* ModulName, const char* FName, void* HookedF, int32_t* OutErrorCode);
	int32_t InitFunctionHookByAddress(Hook_Info** OutputInfo, bool WrapFunction, void* Target, void* HookedF, int32_t* OutErrorCode);

	// Memory custom hook
	int32_t InitHookCustomData(Hook_Info** OutputInfo, void* Target, void* CustomData, size_t CSize, int32_t* OutErrorCode);

	// UnHook
	bool UnHookRegisteredData(int32_t HookID, int32_t* OutErrorCode);
	bool HookAgainRegisteredData(int32_t HookID, int32_t* OutErrorCode);

	// Init And shut down
	bool ServiceGlobalInit(int32_t* OutErrorCode);
	bool ServiceGlobalShutDown(bool UnHook, int32_t* OutErrorCode);

	// Informations
	bool RetrieveHookInfoByID(Hook_Info** OutputInfo, int32_t HookID, int32_t* OutErrorCode);
	bool RetrieveHookIDByInfo(Hook_Info* InputInfo, int32_t* OutHookID, int32_t* OutErrorCode);

	bool ServiceRegisterHookInformation(Hook_Info* InputInfo, int32_t HookID, int32_t* OutErrorCode);
	bool ServiceUnRegisterHookInformation(int32_t HookID, int32_t* OutErrorCode);

	// Arch
	bool Is64BitProcess();

	// Error handler 
	const char* CHRetrieveErrorCodeString(int32_t InErrorCode);
}