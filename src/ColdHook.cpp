/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#include "ColdHook.h"

namespace ColdHook_Vars
{
	bool Inited = false;
	int32_t CurrentID = 0;
	std::multimap<int32_t, Hook_Info> RegisteredHooks;
	std::mutex Thread;

	ZydisDecoder decoder;
	ks_engine* ks;
}

namespace ColdHook_Service
{
	// Private functions:
	static const std::string X86Instructions[23] = { "JMP", "JZ", "JNZ", "JG", "JGE", "JA", "JAE", "JL", "JLE", "JB", "JBE", "JO",
			"JNO", "JE", "JNE", "JS", "JNS", "JCXZ", "JECXZ", "JRCXZ", "LOOP", "LOOPCC", "CALL" };
	static bool IsAssemblerNeeded(const char* Instruction)
	{
		size_t ISLength = std::strlen(Instruction);

		for (size_t c = 0; c < ISLength; c++) {
			for (int i = 0; i < 23; i++) {
				std::string TempIn = X86Instructions[i];
				std::transform(TempIn.begin(), TempIn.end(), TempIn.begin(), ::tolower);
				if (std::memcmp(&Instruction[c], TempIn.c_str(), std::strlen(TempIn.c_str())) == 0) {
					size_t found = 0;
					bool GotOne = false;
					bool SpaceReached = false;
					for (size_t b = c; b < ISLength; b++) {
						if (!SpaceReached) {
							if (Instruction[b] == 0x20) {
								SpaceReached = true;
								if (Instruction[b + 1] == '0' && Instruction[b + 2] == 'x') {
									size_t dst = ISLength - (b + 3);

									if ((dst / 2) != sizeof(void*)) {
										return false;
									}
									// Looks like we have an address 
									return true;
								}
							}
						}
						if (SpaceReached) {
							if (GotOne) {
								if (Instruction[b] == ']') {
									// Is an Address?
									if (Instruction[found] == '0' && Instruction[found + 1] == 'x') {
										size_t dst = b - (found + 2);

										if ((dst / 2) != sizeof(void*)) {
											return false;
										}
										// Looks like we have an address 
										return true;
									}
									// Looks like we don't have an address 
									return false;
								}
							}
							else {
								if (Instruction[b] == '[') {
									found = b + 1;
									GotOne = true;
								}
							}
						}
					}
					// Looks like we don't have an address 
					return false;
				}
			}
		}

		// Check for a constant pointer 
		size_t found = 0;
		bool GotOne = false;
		for (size_t i = 0; i < ISLength; i++) {
			if (Instruction[i] == '[') {
				found = i + 1;
				GotOne = true;
			}
			if (GotOne) {
				if (Instruction[i] == ']') {
					// Is an Address?
					if (Instruction[found] == '0' && Instruction[found + 1] == 'x') {
						size_t dst = i - (found + 2);

						if ((dst / 2) != sizeof(void*)) {
							return false;
						}
						// Looks like we have an address 
						return true;
					}
					// Looks like we don't have an address 
					return false;
				}
			}
		}
		return false;
	}

	//  Disassembler call
	static char Instructions[400] = { 0 };
	static unsigned int DisasmRange(SIZE_T* OutPutInstructionsSize, ULONG_PTR* OutNextInst, SIZE_T HookSize, ULONG_PTR BaseAddressFormat, void* Buffer, void* TrampolineBuffer)
	{
		if (OutPutInstructionsSize > NULL && OutNextInst > NULL && BaseAddressFormat && Buffer > NULL)
		{
			// Declare some function variables
			bool Is64Bit = ColdHook_Service::Is64BitProcess();
			unsigned int DecodedI = 0;
			ZydisFormatter formatter;
			ZyanUSize offset = 0;
			const ZyanUSize length = 0x1000;
			ZydisDecodedInstruction instruction;

			size_t count;
			unsigned char* encode;
			size_t size;

			// Instructions size
			SIZE_T LSize = 0;
			SIZE_T LSize2 = 0;

			memset(Instructions, 0, sizeof(Instructions));

			// We disassemble 0x100 bytes
			ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

			ZyanU64 runtime_address = BaseAddressFormat;
			while (ZydisDecoderDecodeBuffer(&ColdHook_Vars::decoder, (void*)((ULONG_PTR)Buffer + offset), length - offset,
				&instruction) == ZYAN_STATUS_SUCCESS)
			{
				if (LSize >= HookSize) {
					// Store the next instruction
					*OutNextInst = runtime_address;
					break;
				}
				// Format & print the binary instruction structure to human readable format
				ZydisFormatterFormatInstruction(&formatter, &instruction, Instructions, sizeof(Instructions),
					runtime_address);

				if (ColdHook_Service::IsAssemblerNeeded(Instructions)) {	
					int AsmD = ks_asm(ColdHook_Vars::ks, Instructions, (ULONG_PTR)TrampolineBuffer + LSize2, &encode, &size, &count);
					if (AsmD != KS_ERR_OK) {
						return NULL;
					}
					memcpy((void*)((ULONG_PTR)TrampolineBuffer + LSize2), (void*)encode, size);
					LSize2 += size;
					size = 0;
					ks_free(encode);
				}
				else {
					memcpy((void*)((ULONG_PTR)TrampolineBuffer + LSize2), (void*)runtime_address, instruction.length);
					LSize2 += instruction.length;
				}

				offset += instruction.length;
				runtime_address += instruction.length;
				LSize += instruction.length;
				DecodedI++;
			}
			*OutPutInstructionsSize = LSize2;
			return DecodedI;
		}
		return NULL;
	}

	// Generate base address
	static void* AllocateTrampoline(ULONG_PTR StartBaseAddress, SIZE_T PageS, int32_t* OutErrorCode, SIZE_T* ChangedHookSize)
	{
		// Declare some function variables
		ULONG_PTR* StartingBaseAddress = NULL;
		SIZE_T AddressBytesCounter = NULL;
		void* ReturnAddress = NULL;
		SIZE_T Distance = NULL;
		bool IsBack = false;

		if (StartBaseAddress > NULL)
		{
			if (ColdHook_Service::Is64BitProcess())
			{
				StartingBaseAddress = (ULONG_PTR*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);

				if (StartingBaseAddress > NULL)
				{
					*StartingBaseAddress = StartBaseAddress;

					// Loop untill we find a right address 
					for (;;)
					{
						// We give a range of 40MB
						if (Distance > 0x41943040) {
							if (IsBack) {
								if (OutErrorCode > NULL) {
									*OutErrorCode = FALIED_OUT_RANGE;
								}
								// In that case we'll use another method to jump.
								*ChangedHookSize = 0xE;
								ReturnAddress = VirtualAlloc(NULL, PageS, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
								return ReturnAddress;
							}
							// We try searching before the module address
							Distance = NULL;
							*StartingBaseAddress = StartBaseAddress;
							IsBack = true;
						}
						if ((ReturnAddress = VirtualAlloc((void*)* StartingBaseAddress, PageS, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) != NULL)
							break;
						if (!IsBack)
							* StartingBaseAddress += 0x1000;
						else
							*StartingBaseAddress -= 0x1000;
						Distance += 0x1000;
					}
					if (OutErrorCode > NULL) {
						*OutErrorCode = NULL;
					}
					VirtualFree((void*)StartingBaseAddress, 0x1000, MEM_DECOMMIT);
					return ReturnAddress;
				}
				else
				{
					if (OutErrorCode > NULL) {
						*OutErrorCode = FALIED_ALLOCATION;
					}
				}
				return NULL;
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = WARN_32_BIT;
				}
				ReturnAddress = VirtualAlloc(NULL, PageS, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				return ReturnAddress;
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		return NULL;
	}

	// Custom 
	static bool IsAddressRegisteredAsHook(void* Address)
	{
		auto IterS = ColdHook_Vars::RegisteredHooks.begin();
		while (IterS != ColdHook_Vars::RegisteredHooks.end())
		{
			if (IterS->second.HFunction == Address) {
				return true;
			}
			IterS++;
		}
		return false;
	}

	
	// Function wrap hooks
	static BYTE HookDataB[0x100] = { 0 };
	int32_t InitFunctionHookByName(Hook_Info* OutputInfo, bool WrapFunction, bool CheckKBase, const char* ModulName, const char* FName, void* HookedF, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (OutputInfo > NULL && FName > NULL && HookedF > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				FARPROC RequestedFAddress = NULL;
				HMODULE RequestedM = NULL;

				ULONG_PTR TNextInstruction = NULL;
				SIZE_T TrampolineISize = NULL;
				SIZE_T MaxHSize = 5;
				DWORD OldP = NULL;
				int32_t Code = NULL;

				bool BytesStored = false;
				bool Assembled = false;

				void* Redirection = NULL;
				void* JumpTo = NULL;

				std::memset(HookDataB, 0, sizeof(HookDataB));

				// Read module
				RequestedM = GetModuleHandleA(ModulName);
				
				if (RequestedM > NULL)
				{
					// Get function pointer 
					RequestedFAddress = GetProcAddress(RequestedM, FName);

					// Latest windows uses mostly the kernel32 dll as a "bridge" to jump to the reals functions in the kernelbase module.
					if (ModulName > NULL) {
						if (CheckKBase && ColdHook_Service::Is64BitProcess()) {
							HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
							HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
							FARPROC RequestedKbaseF = GetProcAddress(hKernelBase, FName);
							if (RequestedM == hKernel32) {
								if (hKernelBase > NULL && RequestedKbaseF > NULL) {
									// if the first 8 bytes are same, we continue using the requested module name
									if (std::memcmp((void*)RequestedFAddress, (void*)RequestedKbaseF, 8) != 0) {
										RequestedM = hKernelBase;
										RequestedFAddress = RequestedKbaseF;
									}
								}
							}
						}
					}

					if (RequestedFAddress > NULL)
					{
						if (!ColdHook_Service::IsAddressRegisteredAsHook((void*)RequestedFAddress))
						{
							SIZE_T ChangedHookSize = NULL;
							unsigned char* Encode;

							Redirection = ColdHook_Service::AllocateTrampoline((ULONG_PTR)RequestedM, 0x1000, &Code, &ChangedHookSize);
							if (ChangedHookSize != NULL) {
								MaxHSize = ChangedHookSize;
							}
							if (WrapFunction)
							{
								if (Redirection > NULL)
								{
									if (Code == NULL) // If 64 bit hook
									{
										unsigned int DecodedI = ColdHook_Service::DisasmRange(&TrampolineISize, 
											&TNextInstruction, MaxHSize, (ULONG_PTR)RequestedFAddress,
											(void*)RequestedFAddress, 
											(void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*)));

										if (DecodedI != NULL)
										{
											// Install jump to our hooked function.
											*(BYTE*)Redirection = 0xFF;
											*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE)) = 0x25;
											std::memset((void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));

											*(void**)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = HookedF;

											// Apply the return back jump
											*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize) = 0xFF;
											*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize + sizeof(BYTE)) = 0x25;
											std::memset((void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));
											*(void**)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = (void*)TNextInstruction;

											JumpTo = Redirection;
											Redirection = (void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*));
										}
										else
										{
											if (OutErrorCode > NULL) {
												*OutErrorCode = FALIED_DISASSEMBLER;
											}
											ColdHook_Vars::Thread.unlock();
											return NULL;
										}
									}
									else if (Code == FALIED_OUT_RANGE)
									{
										unsigned int DecodedI = ColdHook_Service::DisasmRange(&TrampolineISize, &TNextInstruction, MaxHSize, (ULONG_PTR)RequestedFAddress,
											(void*)RequestedFAddress, Redirection);

										if (DecodedI != NULL)
										{
											*((BYTE*)(ULONG_PTR)Redirection + TrampolineISize) = 0xFF;
											*((BYTE*)(ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE)) = 0x25;
											std::memset((void*)((ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));

											*(void**)((ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = (void*)TNextInstruction;
											JumpTo = HookedF;

											// Hook bytes
											HookDataB[0] = 0xFF;
											HookDataB[1] = 0x25;
											std::memset(&HookDataB[2], NULL, sizeof(DWORD));
											std::memcpy(&HookDataB[6], &JumpTo, sizeof(void*));
											BytesStored = true;
										}
										else
										{
											if (OutErrorCode > NULL) {
												*OutErrorCode = FALIED_DISASSEMBLER;
											}
											ColdHook_Vars::Thread.unlock();
											return NULL;
										}
									}
									else if (Code == WARN_32_BIT)	// 32 bit
									{
										unsigned int DecodedI = ColdHook_Service::DisasmRange(&TrampolineISize, &TNextInstruction, MaxHSize, (ULONG_PTR)RequestedFAddress,
											(void*)RequestedFAddress, Redirection);

										if (DecodedI != NULL)
										{
											// Apply the return back jump
											*((BYTE*)(ULONG_PTR)Redirection + TrampolineISize) = 0xE9;
											ULONG_PTR TempVar = (ULONG_PTR)Redirection + TrampolineISize;
											SIZE_T Jumpoffset = (ULONG_PTR)TNextInstruction - TempVar - MaxHSize;
											std::memcpy((void*)((ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE)), &Jumpoffset, sizeof(DWORD));

											JumpTo = HookedF;
										}
										else
										{
											if (OutErrorCode > NULL) {
												*OutErrorCode = FALIED_DISASSEMBLER;
											}
											ColdHook_Vars::Thread.unlock();
											return NULL;
										}
									}
									else
									{
										if (OutErrorCode > NULL) {
											*OutErrorCode = FALIED_ALLOCATION;
										}
										ColdHook_Vars::Thread.unlock();
										return NULL;
									}
								}
								else
								{
									if (OutErrorCode > NULL) {
										*OutErrorCode = FALIED_ALLOCATION;
									}
									ColdHook_Vars::Thread.unlock();
									return NULL;
								}
							}
							else
							{
								if (Redirection > NULL)
								{
									if (Code == NULL) // If 64 bit hook
									{
										// Install jump to our hooked function.
										*(BYTE*)Redirection = 0xFF;
										*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE)) = 0x25;
										std::memset((void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));

										*(void**)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = HookedF;

										JumpTo = Redirection;
										Redirection = (void*)RequestedFAddress;
									}
									else if (Code == WARN_32_BIT)
									{
										VirtualFree(Redirection, NULL, MEM_RELEASE);
										JumpTo = HookedF;
										Redirection = (void*)RequestedFAddress;
									}
									else if (Code == FALIED_OUT_RANGE)
									{
										JumpTo = HookedF;
										Redirection = (void*)RequestedFAddress;

										// Hook bytes
										HookDataB[0] = 0xFF;
										HookDataB[1] = 0x25;
										std::memset(&HookDataB[2], NULL, sizeof(DWORD));
										std::memcpy(&HookDataB[6], &JumpTo, sizeof(void*));
										BytesStored = true;
									}
									else
									{
										if (OutErrorCode > NULL) {
											*OutErrorCode = FALIED_ALLOCATION;
										}
										ColdHook_Vars::Thread.unlock();
										return NULL;
									}
								}
								else
								{
									if (OutErrorCode > NULL) {
										*OutErrorCode = FALIED_ALLOCATION;
									}
									ColdHook_Vars::Thread.unlock();
									return NULL;
								}
							}
							// Setup our hook
							if (VirtualProtect((void*)RequestedFAddress, MaxHSize, PAGE_EXECUTE_READWRITE, &OldP))
							{
								// Original bytes 
								OutputInfo->OrgData = VirtualAlloc(NULL, MaxHSize + 1, MEM_COMMIT, PAGE_READWRITE);
								OutputInfo->HookData = VirtualAlloc(NULL, MaxHSize + 1, MEM_COMMIT, PAGE_READWRITE);

								if (OutputInfo->OrgData > NULL && OutputInfo->HookData > NULL)
								{
									if (!BytesStored) {
										// Set hook bytes
										HookDataB[0] = 0xE9;
										SIZE_T Jumpoffset = (ULONG_PTR)JumpTo - (ULONG_PTR)RequestedFAddress - MaxHSize;
										std::memcpy(&HookDataB[1], &Jumpoffset, sizeof(DWORD));
									}
									std::memcpy(OutputInfo->OrgData, (void*)RequestedFAddress, MaxHSize);
									std::memcpy((void*)RequestedFAddress, HookDataB, MaxHSize);
									std::memcpy(OutputInfo->HookData, HookDataB, MaxHSize);

									VirtualProtect((void*)RequestedFAddress, MaxHSize, OldP, &OldP);

									if (ModulName > NULL)
										OutputInfo->ModuleName = ModulName;
									else
										OutputInfo->ModuleName = "";

									OutputInfo->FunctionName = FName;

									OutputInfo->HFunction = (void*)RequestedFAddress;
									OutputInfo->HookSize = MaxHSize;

									OutputInfo->OriginalF = Redirection;
									OutputInfo->TrampolinePage = JumpTo;

									OutputInfo->TrampolineSize = 0x1000;

									if (Code == WARN_32_BIT && WrapFunction != true)
										OutputInfo->Trampoline = false;
									else
										OutputInfo->Trampoline = true;

									OutputInfo->StatusHooked = true;

									if (OutErrorCode > NULL) {
										*OutErrorCode = NULL;
									}

									ColdHook_Vars::CurrentID++;
									ColdHook_Vars::Thread.unlock();

									return ColdHook_Vars::CurrentID;
								}
								else
								{
									if (OutErrorCode > NULL) {
										*OutErrorCode = FALIED_ALLOCATION;
									}
								}
							}
							else
							{
								if (OutErrorCode > NULL) {
									*OutErrorCode = FALIED_MEM_PROTECTION;
								}
							}
						}
						else
						{
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_ALREADY_EXISTS;
							}
						}
					}
					else
					{
						if (OutErrorCode > NULL) {
							*OutErrorCode = FALIED_FUNCTION_NOT_FOUND;
						}
					}
				}
				else
				{
					if (OutErrorCode > NULL) {
						*OutErrorCode = FALIED_MODULE_NOT_FOUND;
					}
				}
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return NULL;
	}
	int32_t InitFunctionHookByAddress(Hook_Info* OutputInfo, bool WrapFunction, void* Target, void* HookedF, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (OutputInfo > NULL && Target > NULL && HookedF > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				ULONG_PTR TNextInstruction = NULL;
				SIZE_T TrampolineISize = NULL;
				SIZE_T MaxHSize = 5;
				DWORD OldP = NULL;
				int32_t Code = NULL;

				bool BytesStored = false;

				void* Redirection = NULL;
				void* JumpTo = NULL;

				std::memset(HookDataB, 0, sizeof(HookDataB));

				if (!ColdHook_Service::IsAddressRegisteredAsHook(Target))
				{
					SIZE_T ChangedHookSize = NULL;

					Redirection = ColdHook_Service::AllocateTrampoline((ULONG_PTR)Target, 0x1000, &Code, &ChangedHookSize);
					if (ChangedHookSize != NULL) {
						MaxHSize = ChangedHookSize;
					}
					if (WrapFunction)
					{
						if (Redirection > NULL)
						{
							if (Code == NULL) // If 64 bit hook
							{
								unsigned int DecodedI = ColdHook_Service::DisasmRange(&TrampolineISize, &TNextInstruction, MaxHSize, (ULONG_PTR)Target,
									Target, (void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*)));

								if (DecodedI != NULL)
								{
									// Install jump to our hooked function.
									*(BYTE*)Redirection = 0xFF;
									*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE)) = 0x25;
									std::memset((void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));

									*(void**)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = HookedF;

									// Apply the return back jump
									*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize) = 0xFF;
									*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize + sizeof(BYTE)) = 0x25;
									std::memset((void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));
									*(void**)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*) + TrampolineISize + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = (void*)TNextInstruction;

									JumpTo = Redirection;
									Redirection = (void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD) + sizeof(void*));
								}
								else
								{
									if (OutErrorCode > NULL) {
										*OutErrorCode = FALIED_DISASSEMBLER;
									}
									ColdHook_Vars::Thread.unlock();
									return NULL;
								}
							}
							else if (Code == FALIED_OUT_RANGE)
							{
								unsigned int DecodedI = ColdHook_Service::DisasmRange(&TrampolineISize, &TNextInstruction, MaxHSize, (ULONG_PTR)Target,
									Target, Redirection);
								if (DecodedI != NULL)
								{
									*((BYTE*)(ULONG_PTR)Redirection + TrampolineISize) = 0xFF;
									*((BYTE*)(ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE)) = 0x25;
									std::memset((void*)((ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));

									*(void**)((ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = (void*)TNextInstruction;
									JumpTo = HookedF;

									// Hook bytes
									HookDataB[0] = 0xFF;
									HookDataB[1] = 0x25;
									std::memset(&HookDataB[2], NULL, sizeof(DWORD));
									std::memcpy(&HookDataB[6], &JumpTo, sizeof(void*));
									BytesStored = true;
								}
								else
								{
									if (OutErrorCode > NULL) {
										*OutErrorCode = FALIED_DISASSEMBLER;
									}
									ColdHook_Vars::Thread.unlock();
									return NULL;
								}
							}
							else if (Code == WARN_32_BIT)	// 32 bit
							{
								unsigned int DecodedI = ColdHook_Service::DisasmRange(&TrampolineISize, &TNextInstruction, MaxHSize, (ULONG_PTR)Target,
									Target, Redirection);
								if (DecodedI != NULL)
								{
									// Apply the return back jump
									*((BYTE*)(ULONG_PTR)Redirection + TrampolineISize) = 0xE9;
									ULONG_PTR TempVar = (ULONG_PTR)Redirection + TrampolineISize;
									SIZE_T Jumpoffset = (ULONG_PTR)TNextInstruction - TempVar - MaxHSize;
									std::memcpy((void*)((ULONG_PTR)Redirection + TrampolineISize + sizeof(BYTE)), &Jumpoffset, sizeof(DWORD));

									JumpTo = HookedF;
								}
								else
								{
									if (OutErrorCode > NULL) {
										*OutErrorCode = FALIED_DISASSEMBLER;
									}
									ColdHook_Vars::Thread.unlock();
									return NULL;
								}
							}
							else
							{
								if (OutErrorCode > NULL) {
									*OutErrorCode = FALIED_ALLOCATION;
								}
								ColdHook_Vars::Thread.unlock();
								return NULL;
							}
						}
						else
						{
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_ALLOCATION;
							}
							ColdHook_Vars::Thread.unlock();
							return NULL;
						}
					}
					else
					{
						if (Redirection > NULL)
						{
							if (Code == NULL) // If 64 bit hook
							{
								// Install jump to our hooked function.
								*(BYTE*)Redirection = 0xFF;
								*((BYTE*)(ULONG_PTR)Redirection + sizeof(BYTE)) = 0x25;
								std::memset((void*)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE)), NULL, sizeof(DWORD));

								*(void**)((ULONG_PTR)Redirection + sizeof(BYTE) + sizeof(BYTE) + sizeof(DWORD)) = HookedF;

								JumpTo = Redirection;
								Redirection = Target;
							}
							else if (Code == FALIED_OUT_RANGE)
							{
								JumpTo = HookedF;
								Redirection = Target;

								// Hook bytes
								HookDataB[0] = 0xFF;
								HookDataB[1] = 0x25;
								std::memset(&HookDataB[2], NULL, sizeof(DWORD));
								std::memcpy(&HookDataB[6], &JumpTo, sizeof(void*));
								BytesStored = true;
							}
							else if (Code == WARN_32_BIT) // 32 bit
							{
								VirtualFree(Redirection, NULL, MEM_RELEASE);
								JumpTo = HookedF;
								Redirection = Target;
							}
							else
							{
								if (OutErrorCode > NULL) {
									*OutErrorCode = FALIED_ALLOCATION;
								}
								ColdHook_Vars::Thread.unlock();
								return NULL;
							}
						}
						else
						{
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_ALLOCATION;
							}
							ColdHook_Vars::Thread.unlock();
							return NULL;
						}
					}
					// Setup our hook
					if (VirtualProtect(Target, MaxHSize, PAGE_EXECUTE_READWRITE, &OldP))
					{
						// Original bytes 
						OutputInfo->OrgData = VirtualAlloc(NULL, MaxHSize + 1, MEM_COMMIT, PAGE_READWRITE);
						OutputInfo->HookData = VirtualAlloc(NULL, MaxHSize + 1, MEM_COMMIT, PAGE_READWRITE);

						if (OutputInfo->OrgData > NULL && OutputInfo->HookData > NULL)
						{
							std::memcpy(OutputInfo->OrgData, Target, MaxHSize);

							if (!BytesStored) {
								// Set hook bytes
								HookDataB[0] = 0xE9;								
								SIZE_T Jumpoffset = (ULONG_PTR)JumpTo - (ULONG_PTR)Target - MaxHSize;
								std::memcpy(&HookDataB[1], &Jumpoffset, sizeof(DWORD));
							}
							std::memcpy(OutputInfo->OrgData, Target, MaxHSize);
							std::memcpy(Target, HookDataB, MaxHSize);
							std::memcpy(OutputInfo->HookData, HookDataB, MaxHSize);
							
							VirtualProtect(Target, MaxHSize, OldP, &OldP);

							OutputInfo->FunctionName = "";
							OutputInfo->ModuleName = "";

							OutputInfo->HFunction = Target;
							OutputInfo->HookSize = MaxHSize;

							OutputInfo->OriginalF = Redirection;
							OutputInfo->TrampolinePage = JumpTo;

							OutputInfo->TrampolineSize = 0x1000;

							if (Code == WARN_32_BIT && WrapFunction != true)
								OutputInfo->Trampoline = false;
							else
								OutputInfo->Trampoline = true;

							OutputInfo->StatusHooked = true;

							if (OutErrorCode > NULL) {
								*OutErrorCode = NULL;
							}

							ColdHook_Vars::CurrentID++;
							ColdHook_Vars::Thread.unlock();

							return ColdHook_Vars::CurrentID;
						}
						else
						{
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_ALLOCATION;
							}
						}
					}
					else
					{
						if (OutErrorCode > NULL) {
							*OutErrorCode = FALIED_MEM_PROTECTION;
						}
					}
				}
				else
				{
					if (OutErrorCode > NULL) {
						*OutErrorCode = FALIED_ALREADY_EXISTS;
					}
				}
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return NULL;
	}


	// Memory custom hook
	int32_t InitHookCustomData(Hook_Info* OutputInfo, void* Target, void* CustomData, size_t CSize, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (OutputInfo > NULL && Target > NULL && CustomData > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				if (!ColdHook_Service::IsAddressRegisteredAsHook(Target))
				{
					DWORD OldP = NULL;
					if (VirtualProtect(Target, CSize, PAGE_EXECUTE_READWRITE, &OldP))
					{
						OutputInfo->OrgData = VirtualAlloc(NULL, CSize + 1, MEM_COMMIT, PAGE_READWRITE);
						OutputInfo->HookData = VirtualAlloc(NULL, CSize + 1, MEM_COMMIT, PAGE_READWRITE);

						if (OutputInfo->OrgData > NULL && OutputInfo->HookData > NULL)
						{
							std::memcpy(OutputInfo->OrgData, Target, CSize);
							std::memcpy(OutputInfo->HookData, CustomData, CSize);

							std::memcpy(Target, CustomData, CSize);
							VirtualProtect(Target, CSize, OldP, &OldP);

							OutputInfo->FunctionName = "";
							OutputInfo->ModuleName = "";

							OutputInfo->HFunction = Target;
							OutputInfo->HookSize = CSize;

							OutputInfo->OriginalF = NULL;
							OutputInfo->TrampolinePage = NULL;
							OutputInfo->TrampolineSize = NULL;

							OutputInfo->Trampoline = false;
							OutputInfo->StatusHooked = true;

							if (OutErrorCode > NULL) {
								*OutErrorCode = NULL;
							}

							ColdHook_Vars::CurrentID++;
							ColdHook_Vars::Thread.unlock();

							return ColdHook_Vars::CurrentID;
						}
						else
						{
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_ALLOCATION;
							}
						}
					}
					else
					{
						if (OutErrorCode > NULL) {
							*OutErrorCode = FALIED_MEM_PROTECTION;
						}
					}
				}
				else 
				{
					if (OutErrorCode > NULL) {
						*OutErrorCode = FALIED_ALREADY_EXISTS;
					}
				}
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return NULL;
	}

	// UnHook
	bool UnHookRegisteredData(int32_t HookID, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (HookID > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				DWORD OldP = NULL;
				auto IterS = ColdHook_Vars::RegisteredHooks.begin();
				while (IterS != ColdHook_Vars::RegisteredHooks.end())
				{
					if (IterS->first == HookID) {
						if (IterS->second.StatusHooked) {
							if (VirtualProtect(IterS->second.HFunction, IterS->second.HookSize, PAGE_EXECUTE_READWRITE, &OldP)) {
								std::memcpy(IterS->second.HFunction, IterS->second.OrgData, IterS->second.HookSize);
								VirtualProtect(IterS->second.HFunction, IterS->second.HookSize, OldP, &OldP);
								IterS->second.StatusHooked = false;
								if (OutErrorCode > NULL) {
									*OutErrorCode = NULL;
								}
								ColdHook_Vars::Thread.unlock();
								return true;
							}
							else {
								if (OutErrorCode > NULL) {
									*OutErrorCode = FALIED_UNHOOK;
								}
								ColdHook_Vars::Thread.unlock();
								return false;
							}
						}
						else {
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_NOT_HOOKED;
							}
							ColdHook_Vars::Thread.unlock();
							return false;
						}
					}
					IterS++;
				}
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_HOOK_NOT_EXISTS;
				}
				ColdHook_Vars::Thread.unlock();
				return false;
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}
	bool HookAgainRegisteredData(int32_t HookID, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (HookID > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				DWORD OldP = NULL;
				auto IterS = ColdHook_Vars::RegisteredHooks.begin();
				while (IterS != ColdHook_Vars::RegisteredHooks.end())
				{
					if (IterS->first == HookID) {
						if (!IterS->second.StatusHooked) {
							if (VirtualProtect(IterS->second.HFunction, IterS->second.HookSize, PAGE_EXECUTE_READWRITE, &OldP)) {
								std::memcpy(IterS->second.HFunction, IterS->second.HookData, IterS->second.HookSize);
								VirtualProtect(IterS->second.HFunction, IterS->second.HookSize, OldP, &OldP);
								IterS->second.StatusHooked = true;
								if (OutErrorCode > NULL) {
									*OutErrorCode = NULL;
								}
								ColdHook_Vars::Thread.unlock();
								return true;
							}
							else {
								if (OutErrorCode > NULL) {
									*OutErrorCode = FALIED_HOOK;
								}
								ColdHook_Vars::Thread.unlock();
								return false;
							}
						}
						else {
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_ALREADY_EXISTS;
							}
							ColdHook_Vars::Thread.unlock();
							return false;
						}
					}
					IterS++;
				}
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_HOOK_NOT_EXISTS;
				}
				ColdHook_Vars::Thread.unlock();
				return false;
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}

	// Init And shut down
	bool ServiceGlobalInit(int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (!ColdHook_Vars::Inited)
		{
			if (!ColdHook_Vars::RegisteredHooks.empty()) {
				ColdHook_Vars::RegisteredHooks.clear();
			}
			if (OutErrorCode > NULL) {
				*OutErrorCode = NULL;
			}

			// Init Zydis and Keystone
			ks_err err;
			if (ColdHook_Service::Is64BitProcess()) {
				ZydisDecoderInit(&ColdHook_Vars::decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
				err = ks_open(KS_ARCH_X86, KS_MODE_64, &ColdHook_Vars::ks);
			}
			else {
				ZydisDecoderInit(&ColdHook_Vars::decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
				err = ks_open(KS_ARCH_X86, KS_MODE_32, &ColdHook_Vars::ks);
			}
			if (err != KS_ERR_OK) {
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_KEYSTONE_INIT;
				}
				ColdHook_Vars::Thread.unlock();
				return false;
			}
			ColdHook_Vars::Inited = true;
			ColdHook_Vars::CurrentID = NULL;
			ColdHook_Vars::Thread.unlock();

			return true;
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_ALREADY_INITIALIZED;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}
	bool ServiceGlobalShutDown(int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (ColdHook_Vars::Inited)
		{
			DWORD OldP = NULL;
			int32_t ErrorC = NULL;
			auto IterS = ColdHook_Vars::RegisteredHooks.begin();

			if (!ColdHook_Vars::RegisteredHooks.empty())
			{
				while (IterS != ColdHook_Vars::RegisteredHooks.end())
				{
					if (IterS->second.StatusHooked)
					{
						if (VirtualProtect(IterS->second.HFunction, IterS->second.HookSize, PAGE_EXECUTE_READWRITE, &OldP))
						{
							std::memcpy(IterS->second.HFunction, IterS->second.OrgData, IterS->second.HookSize);
							VirtualProtect(IterS->second.HFunction, IterS->second.HookSize, OldP, &OldP);
							if (!VirtualFree(IterS->second.OrgData, IterS->second.HookSize + 1, MEM_DECOMMIT)) {
								ErrorC = FALIED_FREE_MEMORY;
								if (OutErrorCode > NULL) {
									*OutErrorCode = ErrorC;
								}
								ColdHook_Vars::Thread.unlock();
								return false;
							}
							if (!VirtualFree(IterS->second.HookData, IterS->second.HookSize + 1, MEM_DECOMMIT)) {
								ErrorC = FALIED_FREE_MEMORY;
								if (OutErrorCode > NULL) {
									*OutErrorCode = ErrorC;
								}
								ColdHook_Vars::Thread.unlock();
								return false;
							}

							if (IterS->second.Trampoline)
							{
								if (!VirtualFree(IterS->second.TrampolinePage, NULL, MEM_RELEASE)) {
									ErrorC = FALIED_FREE_MEMORY;
									if (OutErrorCode > NULL) {
										*OutErrorCode = ErrorC;
									}
									ColdHook_Vars::Thread.unlock();
									return false;
								}
							}
						}
						else {
							ErrorC = FALIED_UNHOOK;
							if (OutErrorCode > NULL) {
								*OutErrorCode = ErrorC;
							}
							ColdHook_Vars::Thread.unlock();
							return false;
						}
					}
					else
					{
						if (IterS->second.Trampoline)
						{
							if (!VirtualFree(IterS->second.TrampolinePage, NULL, MEM_RELEASE)) {
								ErrorC = FALIED_FREE_MEMORY;
							}
						}
					}
					ColdHook_Vars::RegisteredHooks.erase(IterS);
					IterS++;
				}
			}
			if (OutErrorCode > NULL) {
				*OutErrorCode = ErrorC;
			}

			ks_close(ColdHook_Vars::ks);
			ColdHook_Vars::Inited = false;
			ColdHook_Vars::CurrentID = NULL;
			ColdHook_Vars::Thread.unlock();

			return true;
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}

	// Informations
	bool RetrieveHookInfoByID(Hook_Info* OutputInfo, int32_t HookID, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (OutputInfo > NULL && HookID > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				auto IterS = ColdHook_Vars::RegisteredHooks.begin();
				while (IterS != ColdHook_Vars::RegisteredHooks.end())
				{
					if (IterS->first == HookID) {
						std::memcpy(OutputInfo, &IterS->second, sizeof(Hook_Info));
						if (OutErrorCode > NULL) {
							*OutErrorCode = NULL;
						}
						ColdHook_Vars::Thread.unlock();
						return true;
					}
					IterS++;
				}
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_HOOK_NOT_EXISTS;
				}
				ColdHook_Vars::Thread.unlock();
				return false;
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}
	bool RetrieveHookIDByInfo(Hook_Info* InputInfo, int32_t* OutHookID, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (InputInfo > NULL && OutHookID > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				auto IterS = ColdHook_Vars::RegisteredHooks.begin();
				while (IterS != ColdHook_Vars::RegisteredHooks.end())
				{
					if (std::memcmp(InputInfo, &IterS->second, sizeof(Hook_Info)) == 0) {
						*OutHookID = IterS->first;
						if (OutErrorCode > NULL) {
							*OutErrorCode = NULL;
						}
						ColdHook_Vars::Thread.unlock();
						return true;
					}
					IterS++;
				}
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_HOOK_NOT_EXISTS;
				}
				ColdHook_Vars::Thread.unlock();
				return false;
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}

	bool ServiceRegisterHookInformation(Hook_Info* InputInfo, int32_t HookID, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (InputInfo > NULL && HookID > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				Hook_Info hkinfo;
				std::memcpy(&hkinfo, InputInfo, sizeof(Hook_Info));

				// Check if is already registered
				auto IterS = ColdHook_Vars::RegisteredHooks.begin();
				while (IterS != ColdHook_Vars::RegisteredHooks.end())
				{
					if (IterS->first == HookID) {
						if (OutErrorCode > NULL) {
							*OutErrorCode = FALIED_ALREADY_EXISTS;
						}
						ColdHook_Vars::Thread.unlock();
						return false;
					}
					if (std::memcmp(InputInfo, &IterS->second, sizeof(Hook_Info)) == 0) {
						if (OutErrorCode > NULL) {
							*OutErrorCode = FALIED_ALREADY_EXISTS;
						}
						ColdHook_Vars::Thread.unlock();
						return false;
					}
					IterS++;
				}
				ColdHook_Vars::RegisteredHooks.insert(std::make_pair(HookID, hkinfo));
				if (OutErrorCode > NULL) {
					*OutErrorCode = NULL;
				}
				ColdHook_Vars::Thread.unlock();
				return true;
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}
	bool ServiceUnRegisterHookInformation(int32_t HookID, int32_t* OutErrorCode)
	{
		// Safe thread 
		ColdHook_Vars::Thread.lock();

		if (HookID > NULL)
		{
			if (ColdHook_Vars::Inited)
			{
				// Check if is registered
				auto IterS = ColdHook_Vars::RegisteredHooks.begin();
				while (IterS != ColdHook_Vars::RegisteredHooks.end())
				{
					if (IterS->first == HookID) {
						if (!IterS->second.StatusHooked) {
							ColdHook_Vars::RegisteredHooks.erase(IterS);
							if (OutErrorCode > NULL) {
								*OutErrorCode = NULL;
							}
							ColdHook_Vars::Thread.unlock();
							return true;
						}
						else {
							if (OutErrorCode > NULL) {
								*OutErrorCode = FALIED_NOT_ALLOWED;
							}
							ColdHook_Vars::Thread.unlock();
							return false;
						}
					}
					IterS++;
				}
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NOT_EXISTS;
				}
				ColdHook_Vars::Thread.unlock();
				return false;
			}
			else
			{
				if (OutErrorCode > NULL) {
					*OutErrorCode = FALIED_NEEDS_INITIALIZATION;
				}
			}
		}
		else
		{
			if (OutErrorCode > NULL) {
				*OutErrorCode = FALIED_INVALID_PARAMETER;
			}
		}
		ColdHook_Vars::Thread.unlock();
		return false;
	}

	// Arch
	bool Is64BitProcess()
	{
#ifdef _WIN64
		return true;
#else
		return false;
#endif
	}

	// Error handler 
	const char* CHRetrieveErrorCodeString(int32_t InErrorCode)
	{
		const char* ErrorString;
		switch (InErrorCode)
		{
		case NULL:
			ErrorString = "SUCCESS_NO_ERROR";
			break;
		case FALIED_NEEDS_INITIALIZATION:
			ErrorString = "FALIED_NEEDS_INITIALIZATION";
			break;
		case FALIED_ALREADY_INITIALIZED:
			ErrorString = "FALIED_ALREADY_INITIALIZED";
			break;
		case FALIED_HOOK_EXISTS:
			ErrorString = "FALIED_HOOK_EXISTS";
			break;
		case FALIED_HOOK_NOT_EXISTS:
			ErrorString = "FALIED_HOOK_NOT_EXISTS";
			break;
		case FALIED_BUFFER_CREATION:
			ErrorString = "FALIED_BUFFER_CREATION";
			break;
		case FALIED_INVALID_PARAMETER:
			ErrorString = "FALIED_INVALID_PARAMETER";
			break;
		case FALIED_ALREADY_EXISTS:
			ErrorString = "FALIED_ALREADY_EXISTS";
			break;
		case FALIED_NOT_EXISTS:
			ErrorString = "FALIED_NOT_EXISTS";
			break;
		case FALIED_FREE_MEMORY:
			ErrorString = "FALIED_FREE_MEMORY";
			break;
		case FALIED_UNHOOK:
			ErrorString = "FALIED_UNHOOK";
			break;
		case FALIED_HOOK:
			ErrorString = "FALIED_HOOK";
			break;
		case FALIED_NOT_ALLOWED:
			ErrorString = "FALIED_NOT_ALLOWED";
			break;
		case FALIED_NOT_HOOKED:
			ErrorString = "FALIED_NOT_HOOKED";
			break;
		case FALIED_ALLOCATION:
			ErrorString = "FALIED_ALLOCATION";
			break;
		case FALIED_NO_ACCESS:
			ErrorString = "FALIED_NO_ACCESS";
			break;
		case FALIED_DISASSEMBLER:
			ErrorString = "FALIED_DISASSEMBLER";
			break;
		case FALIED_MEM_PROTECTION:
			ErrorString = "FALIED_MEM_PROTECTION";
			break;
		case FALIED_MODULE_NOT_FOUND:
			ErrorString = "FALIED_MODULE_NOT_FOUND";
			break;
		case FALIED_FUNCTION_NOT_FOUND:
			ErrorString = "FALIED_FUNCTION_NOT_FOUND";
			break;
		case FALIED_OUT_RANGE:
			ErrorString = "FALIED_OUT_RANGE";
			break;
		case FALIED_KEYSTONE_INIT:
			ErrorString = "FALIED_KEYSTONE_INIT";
			break;
		case WARN_32_BIT:
			ErrorString = "WARN_32_BIT";
			break;
		default:
			ErrorString = "Unknown error";
			break;
		}
		return ErrorString;
	}
}