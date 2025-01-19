#include <Windows.h>
#include <metahost.h>
#include <wrl/client.h>

#include <cstdio>

#pragma comment(lib, "MSCorEE.lib")

#define ArraySize(x) (sizeof x / sizeof x[0])

#define CHECK_HRESULT(hrcall) \
    if (HRESULT hr = hrcall; FAILED(hr)) { \
        printf("ERROR: %s failed w/hr 0x%08lx\n", #hrcall, hr); \
        return 1; \
    }

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library)
#import <mscorlib.tlb> raw_interfaces_only					\
	high_property_prefixes("_get","_put","_putref")			\
	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")

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
    BOOL CLRLoaded = FALSE;
    LPCWSTR sz_runtimeVersion = L"v4.0.30319";
    while (pRuntimeEnum->Next(1, &pUnkown, NULL) == S_OK) {

        if (HRESULT hr = pUnkown->QueryInterface(IID_PPV_ARGS(&pRuntimeInfo)); FAILED(hr)) {
            continue;
        }

        WCHAR   wszVersion[64]    = { 0 };
        DWORD   cchVersion        = ArraySize(wszVersion);

        if (HRESULT hr = pRuntimeInfo->GetVersionString(wszVersion, &cchVersion); FAILED(hr)) {
            continue;
        }

        if (lstrcmpW(wszVersion, sz_runtimeVersion) == 0) {
            CLRLoaded = TRUE;
            break;
        }

    }

    if (!CLRLoaded) {
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

    if (!CLRLoaded) {
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

    ExecuteAssembly(pSafeArray, params, appDomainName);
    return 0;
}
