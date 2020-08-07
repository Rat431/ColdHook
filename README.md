# ColdHook

ColdHook is a mini and simple open source memory hooking library for Windows x86/x64 made in C++. This library is mainly intended for a simple usage and especially for whoever has a small knowlegde of how hooks actually works. If you find any issue, feel free to report.

Read the functions documentation just below to understand how ColdHook must be used.

## Features

  - Function hooking (Wrap mode, Function emulation mode).
  - Custom bytes hooking (Ability to hook custom bytes provided by the user to a specified memory address).
  - Ability to unhook/hook again with a single call once the hooking procedure is initialized.
  - Ability to return the error ID if any error occurs during the library execution.
  - Ability to re-calculate special instructions if needed.

## Build requirements
- MSVC 2019 or higher build tools are required to compile this project.

# Functions documentation

- ## InitFunctionHookByName

    ***This function Initializes a new hook by name.***
    -  #### Syntax
        ```cpp
            int32_t InitFunctionHookByName(
                Hook_Info* OutputInfo, 
                bool WrapFunction, 
                bool CheckKBase, 
                const char* ModulName, 
                const char* FName, 
                void* HookedF, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
        - `OutputInfo`
    
            A pointer to the **Hook_Info** structure to retrieve hook informations.
            
        - `WrapFunction`
    
            If this argument is **false**, the function will only pass the control to the provided function without the returning back option. ***Intended if you need to emulate the target function,*** otherwise set to **true** if you still need to call the original hooked function once you handled what you had to.
            
        - `CheckKBase`
            
            If this argument is **true** and the requested module name is **kernel32.dll**, the function will check if the **kernelbase.dll** module is present, if yes, the hook will be placed to the requested function on the **kernelbase.dll** module instead.

        - `ModulName`
    
            A string buffer pointer of the module name that the hook target function is present at. If this paramater is **NULL**, the considered module will be the executable one.
            
        - `FName`
    
            A string buffer pointer of the target desired function name where the hook must be installed to.
            
        - `HookedF`
    
            A function pointer where you wish to redirect the target function.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is an ID of the new hook that can be registered to the system later. If the function fails the return value is **NULL**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
          
- ## InitFunctionHookByAddress

    ***This function Initializes a new hook by addresses.***
    -  #### Syntax
        ```cpp
            int32_t InitFunctionHookByAddress(
                Hook_Info* OutputInfo, 
                bool WrapFunction, 
                void* Target, 
                void* HookedF, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
        - `OutputInfo`
    
            A pointer to the **Hook_Info** structure to retrieve hook informations.
            
        - `WrapFunction`
    
            If this argument is **false**, the function will only pass the control to the provided function without the returning back option. ***Intended if you need to emulate the target function,*** otherwise set to **true** if you still need to call the original hooked function once you handled what you had to.
            
        - `Target`
            
            A pointer to the function that should be hooked.
            
        - `HookedF`
    
            A function pointer where you wish to redirect the target function.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is an ID of the new hook that can be registered to the system later. If the function fails the return value is **NULL**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## InitHookCustomData

    ***This function Initializes a new hook using custom bytes provided by the user.***
    -  #### Syntax
        ```cpp
            int32_t InitHookCustomData(
                Hook_Info* OutputInfo, 
                void* Target, 
                void* CustomData, 
                size_t CSize, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
        - `OutputInfo`
    
            A pointer to the **Hook_Info** structure to retrieve hook informations.
            
        - `Target`
            
            A pointer to the buffer that should be hooked.
            
        - `CustomData`
    
            A function pointer where you wish to redirect the target function.
            
        - `CSize`
    
            The size in bytes that should be hooked.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is an ID of the new hook that can be registered to the system later. If the function fails the return value is **NULL**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## UnHookRegisteredData

    ***This function restores the original bytes to the requested hook ID***
    -  #### Syntax
        ```cpp
            bool UnHookRegisteredData(
                int32_t HookID, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
        - `HookID`
    
            The hook ID returned by the hook initialisers functions.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## HookAgainRegisteredData

    ***This function restores the hook bytes to the requested hook ID***
    -  #### Syntax
        ```cpp
            bool HookAgainRegisteredData(
                int32_t HookID, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
        - `HookID`
    
            The hook ID returned by the hook initialisers functions.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## ServiceGlobalInit

    ***This function initializes the ColdHook service***
    -  #### Syntax
        ```cpp
            bool ServiceGlobalInit(int32_t* OutErrorCode);
         ```
    - ### Arguments
    
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## ServiceGlobalShutDown

    ***This function stops the ColdHook service and unhooks the data if any***
    -  #### Syntax
        ```cpp
            bool ServiceGlobalShutDown(bool UnHook, int32_t* OutErrorCode);
         ```
    - ### Arguments
    
		- `UnHook`	
		
			If this argument is set to **true**, every registered hooked function/address bytes will be restored, otherwise set it to **false**.
			
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## RetrieveHookInfoByID

    ***This function retrieves the registered Hook_Info structure by the ID.***
    -  #### Syntax
        ```cpp
            bool RetrieveHookInfoByID(
                Hook_Info* OutputInfo, 
                int32_t HookID, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
    
        - `OutputInfo`
    
            A pointer to the **Hook_Info** structure to retrieve hook informations.
    
        - `HookID`
    
            The hook ID returned by the hook initialisers functions.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## RetrieveHookIDByInfo

    ***This function retrieves the registered hook ID structure by the Hook_Info structure.***
    -  #### Syntax
        ```cpp
            bool RetrieveHookIDByInfo(
                Hook_Info* InputInfo, 
                int32_t* OutHookID, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
    
        - `InputInfo`
    
            A pointer to the **Hook_Info** structure to give hook informations.
    
        - `OutHookID`
    
             A pointer to a variable that will recieve the registered hook ID.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## ServiceRegisterHookInformation

    ***This function stores on the ColdHook service the returned hook ID and the Hook_Info structure. This must be called when a new hook is initialized***
    -  #### Syntax
        ```cpp
           bool ServiceRegisterHookInformation(
                Hook_Info* InputInfo, 
                int32_t HookID, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
    
        - `InputInfo`
    
            A pointer to the **Hook_Info** structure to give the hook informations.
    
        - `HookID`
    
            The hook ID returned by the hook initialisers functions.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## ServiceUnRegisterHookInformation

    ***This function removes on the ColdHook service the returned hook ID and the Hook_Info structure. This must be called when a new hook is initialized, this must not be called if the Hook ID status is still hooked***
    -  #### Syntax
        ```cpp
           bool ServiceUnRegisterHookInformation(
                int32_t HookID, 
                int32_t* OutErrorCode);
         ```
    - ### Arguments
    
        - `HookID`
    
            The hook ID returned by the hook initialisers functions.
            
        - `OutErrorCode`
        
            A pointer to a variable that will recieve the error id if the function fails. This paramater can be **NULL**.
            
    -  #### Return value
        
          If the function succeeds, the return value is **true**. If the function fails the return value is **false**. For more informations check the error ID stored in the variable provided in the `OutErrorCode` argument.
          
- ## CHRetrieveErrorCodeString

    ***This function retrieves the string of the requested error code ID***
    -  #### Syntax
        ```cpp
           const char* CHRetrieveErrorCodeString(int32_t InErrorCode);
         ```
    - ### Arguments
            
        - `InErrorCode`
            
            An **int32_t** value which contains the error code ID.
            
    -  #### Return value
        
          If the function succeeds, the return value is the string of the requested error code ID. If the function fails the return value is **Unknown error** as string.
          
## Credits
- [Zydis](https://github.com/zyantific/zydis) disassembler for the hook trampoline
- MSDN: Documentation style.

## Some notes
- This project is also used on [ColdAPI project](https://github.com/Rat431/ColdAPI_Steam), maybe something insteresting to look at.
