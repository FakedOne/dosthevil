#pragma once

#ifndef _GETPEFILEINFO__H__H__H
#define _GETPEFILEINFO__H__H__H

#include <Windows.h>
#include <wintrust.h>

#define MakePtr(cast, ptr, addValue) ((cast)((DWORD_PTR)(ptr) + (DWORD_PTR)(addValue)))


#ifndef _WIN64
	typedef DWORD IDTYPE;
	typedef LPDWORD PIDTYPE;
#else
	typedef ULONGLONG IDTYPE;
	typedef PULONGLONG PIDTYPE;
#endif


typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR
{
	union
	{
		DWORD AllAttributes;
		struct
		{
			DWORD RvaBased:1;
			DWORD ReservedAttributes:31;
		} DUMMYSTRUCTNAME;
	} Attributes;

	DWORD DllNameRVA;
	DWORD ModuleHandleRVA;
	DWORD ImportAddressTableRVA;
	DWORD ImportNameTableRVA;
	DWORD BoundImportAddressTableRVA;
	DWORD UnloadInformationTableRVA;
	DWORD TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;

class CPeFile
{
public:
	CPeFile();
	~CPeFile();

public:
	DWORD Attach(LPCTSTR lpszFilePath);
	void Detach();
	DWORD GetAttachInfo() const;

public:
	HANDLE GetFileHandle() const;
	DWORD_PTR GetMappedFileStart() const;
	DWORD_PTR GetMappedFileOffset(DWORD dwFoa) const;
	const IMAGE_DOS_HEADER* GetDosHeader() const;
	DWORD GetDosEntryPoint() const;

public:
	const IMAGE_NT_HEADERS32* GetNtHeader() const;
	BOOL Is64Bit() const;
	ULONGLONG GetImageBase() const;
	const IMAGE_DATA_DIRECTORY* GetDataDirectory() const;
	DWORD GetDataDirectoryEntryRva(DWORD dwIndex) const;
	const IMAGE_SECTION_HEADER* GetSectionHeader(LPWORD lpSectionNum = NULL) const;
	BOOL RvaToFoa(DWORD dwRva, LPDWORD lpFoa = NULL, LPWORD lpSection = NULL) const;
	BOOL FoaToRva(DWORD dwFoa, LPDWORD lpRva = NULL, LPWORD lpSection = NULL) const;
	DWORD VaToRva(DWORD dwVa) const;
	DWORD VaToRva(ULONGLONG ullVa) const;
	ULONGLONG RvaToVa(DWORD dwRva) const;

public:
	BOOL ReadExport();
	BOOL ReadImport();
	BOOL ReadResource();
	BOOL ReadException();
	BOOL ReadSecurity();
	BOOL ReadBaseRelocation();
	BOOL ReadDebug();
	BOOL ReadTLS();
	BOOL ReadLoadConfig();
	BOOL ReadBoundImport();
	BOOL ReadDelayImport();
	void ClearExport();
	void ClearImport();
	void ClearResource();
	void ClearException();
	void ClearSecurity();
	void ClearBaseRelocation();
	void ClearDebug();
	void ClearTLS();
	void ClearLoadConfig();
	void ClearBoundImport();
	void ClearDelayImport();
	void ClearAll();
	BOOL IsReadExport() const;
	BOOL IsReadImport() const;
	BOOL IsReadResource() const;
	BOOL IsReadException() const;
	BOOL IsReadSecurity() const;
	BOOL IsReadBaseRelocation() const;
	BOOL IsReadDebug() const;
	BOOL IsReadTLS() const;
	BOOL IsReadLoadConfig() const;
	BOOL IsReadBoundImport() const;
	BOOL IsReadDelayImport() const;

public:
	const IMAGE_EXPORT_DIRECTORY* GetExportDirectory() const;
	const DWORD* GetExportFunction(LPDWORD lpFuncNum = NULL) const;
	const DWORD* GetExportName(LPDWORD lpNameNum = NULL) const;
	const WORD* GetExportNameOrdinal(LPDWORD lpNameNum = NULL) const;
	DWORD ParseExportFunction(DWORD dwIndex) const;

public:
	const IMAGE_IMPORT_DESCRIPTOR* GetImportDescriptor(LPDWORD lpImportDescriptorNum = NULL) const;
	const IMAGE_THUNK_DATA32* GetImportThunkData(DWORD iImport, LPDWORD lpCount = NULL) const;
	int ParseThunkData(const IMAGE_THUNK_DATA32* lpThunk, LPDWORD lpParam = NULL) const;

public:
	int GetFirstResourceId(PIDTYPE lpFirstID) const;
	int GetNextResourceId(IDTYPE Id, DWORD iRes, PIDTYPE NextID) const;
	const IMAGE_RESOURCE_DIRECTORY* ParseResourceDirectory(IDTYPE Id, LPDWORD lpEntryNum = NULL, LPDWORD lpLevel = NULL, IMAGE_RESOURCE_DIRECTORY_ENTRY** lpResourceEntry = NULL) const;
	const IMAGE_RESOURCE_DATA_ENTRY* ParseResourceData(IDTYPE Id) const;
	int ParseResourceDirectoryEntry(const IMAGE_RESOURCE_DIRECTORY_ENTRY* lpEntry, LPDWORD dwParam) const;
	
public:
	const IMAGE_RUNTIME_FUNCTION_ENTRY* GetRuntimeFunction(LPDWORD lpRuntimeFunctionNum = NULL) const;

public:
	const WIN_CERTIFICATE* const* GetCertificate(LPDWORD lpCertificateNum = NULL) const;

public:
	const IMAGE_BASE_RELOCATION* const* GetBaseRelocation(LPDWORD lpBaseRelocationNum = NULL) const;
	const WORD* GetBaseRelocationBlock(const IMAGE_BASE_RELOCATION* lpBaseRelocation, LPDWORD lpCount = NULL) const;
	static WORD ParseBaseRelocationBlock(WORD wBaseRelocationBlock, LPWORD lpParam = NULL);

public:
	const IMAGE_DEBUG_DIRECTORY* GetDebugDirectory(LPDWORD lpDebugDirectoryNum = NULL) const;
	LPCVOID GetDebugInfoStart(DWORD dwIndex);

public:
	const IMAGE_TLS_DIRECTORY32* GetTLSDirectory() const;
	const DWORD* GetTLSCallback(LPDWORD lpCallbackNum = NULL) const;

public:
	const IMAGE_LOAD_CONFIG_DIRECTORY32* GetLoadConfigDirectory() const;
	
public:
	const IMAGE_BOUND_IMPORT_DESCRIPTOR* const* GetBoundImportDescriptor(LPDWORD lpBoundImportNum = NULL) const;
	const IMAGE_BOUND_FORWARDER_REF* GetBoundImportForwarderRef(DWORD iBoundImport, LPDWORD lpRefNum = NULL) const;

public:
	const IMAGE_DELAYLOAD_DESCRIPTOR* GetDelayImportDescriptor(LPDWORD lpDelayImportNum = NULL) const;


	/*！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！*/


//private:
//	CPeFile(const CPeFile&);
//	CPeFile(const CPeFile&&);
//	CPeFile& operator=(const CPeFile&);
//	CPeFile& operator=(const CPeFile&&);

protected:
	class CPeExportManager
	{
	public:
		CPeExportManager();
		BOOL Initialize(IMAGE_EXPORT_DIRECTORY* lpExportStart, const CPeFile* lpPe);
	public:
		IMAGE_EXPORT_DIRECTORY* m_lpExportDirectory;
		DWORD* m_lpExportFunction;
		DWORD* m_lpExportName;
		WORD* m_lpExportNameOrdinal;
	};
	class CPeImportManager
	{
	public:
		CPeImportManager();
		~CPeImportManager();
		BOOL Initialize(IMAGE_IMPORT_DESCRIPTOR* lpImportStart, const CPeFile* lpPe);
	public:
		DWORD m_dwImportDescriptorNum;
		IMAGE_IMPORT_DESCRIPTOR* m_lpImportDescriptor;
		DWORD* m_lpThunkDataCount;
		IMAGE_THUNK_DATA32** m_lpThunkData;
	};
	class CPeResourceManager
	{
	public:
		CPeResourceManager(IMAGE_RESOURCE_DIRECTORY* lpResourceStart);
		~CPeResourceManager();
	protected:
		CPeResourceManager();
		void SearchResource(IMAGE_RESOURCE_DIRECTORY* lpResourceDirectory, DWORD dwLevel, IMAGE_RESOURCE_DIRECTORY* lpResourceStart);
	public:
		DWORD m_dwLevel;
		IMAGE_RESOURCE_DIRECTORY* m_lpResourceDirectory;
		DWORD m_dwResourceDirectoryEntryNum;
		CPeResourceManager* m_lpNext;
	};
	class CPeExceptionManager
	{
	public:
		CPeExceptionManager(IMAGE_RUNTIME_FUNCTION_ENTRY* lpRuntimeFunctionStart, const CPeFile* lpPe);
	public:
		DWORD m_dwRuntimeFunctionNum;
		IMAGE_RUNTIME_FUNCTION_ENTRY* m_lpRuntimeFunctionStart;
	};
	class CPeSecurityManager
	{
	public:
		CPeSecurityManager(WIN_CERTIFICATE* lpSecurityStart, DWORD dwSize);
		~CPeSecurityManager();
	public:
		DWORD m_dwSecuritNum;
		WIN_CERTIFICATE** m_lpSecurity;
	};
	class CPeBaseRelocationManager
	{
	public:
		CPeBaseRelocationManager(IMAGE_BASE_RELOCATION* lpBaseRelocationStart);
		~CPeBaseRelocationManager();
	public:
		DWORD m_dwBaseRelocationNum;
		IMAGE_BASE_RELOCATION** m_lpBaseRelocation;
	};
	class CPeDebugManager
	{
	public:
		CPeDebugManager(IMAGE_DEBUG_DIRECTORY* lpDebugStart, const CPeFile* lpPe);
	public:
		DWORD m_dwDebugDirectoryNum;
		IMAGE_DEBUG_DIRECTORY* m_lpDebugDirectory;
	};
	class CPeTLSManager
	{
	public:
		BOOL Initialize(IMAGE_TLS_DIRECTORY32* lpTLSStart, const CPeFile* lpPe);
	public:
		IMAGE_TLS_DIRECTORY32* m_lpTLSDirectory;
		DWORD* m_lpTLSCallback;
		DWORD m_dwTLSCallbackNum;
	};
	class CPeLoadConfigManager
	{
	public:
		CPeLoadConfigManager(IMAGE_LOAD_CONFIG_DIRECTORY32* lpLoadConfigStart);
	public:
		IMAGE_LOAD_CONFIG_DIRECTORY32* m_lpLoadConfigDirectory;
	};
	class CPeBoundImportManager
	{
	public:
		CPeBoundImportManager(IMAGE_BOUND_IMPORT_DESCRIPTOR* lpBoundImportStart);
		~CPeBoundImportManager();
	public:
		DWORD m_dwBoundImportDescriptorNum;
		IMAGE_BOUND_IMPORT_DESCRIPTOR** m_lpBoundImportDescriptor;
	};
	class CPeDelayImportManager
	{
	public:
		CPeDelayImportManager(IMAGE_DELAYLOAD_DESCRIPTOR* lpDelayImportStart);
	public:
		DWORD m_dwDelayImportDescriptorNum;
		IMAGE_DELAYLOAD_DESCRIPTOR* m_lpDelayImportDescriptor;
	};

protected:
	int OpenPeFile(LPCTSTR lpszFilePath);
	void CloseFile();
	DWORD CheckHeaders();
	BOOL ReadExportAux();
	BOOL ReadImportAux();
	BOOL ReadResourceAux();
	BOOL ReadExceptionAux();
	BOOL ReadSecurityAux();
	BOOL ReadBaseRelocationAux();
	BOOL ReadDebugAux();
	BOOL ReadTLSAux();
	BOOL ReadLoadConfigAux();
	BOOL ReadBoundImportAux();
	BOOL ReadDelayImportAux();
	void ClearExportAux();
	void ClearImportAux();
	void ClearResourceAux();
	void ClearExceptionAux();
	void ClearSecurityAux();
	void ClearBaseRelocationAux();
	void ClearDebugAux();
	void ClearTLSAux();
	void ClearLoadConfigAux();
	void ClearBoundImportAux();
	void ClearDelayImportAux();

protected:
	HANDLE m_hFile;
	HANDLE m_hFileMap;
	LPVOID m_lpMemory;
	DWORD m_dwType;
	BOOL m_b64Bit;
	IMAGE_DOS_HEADER* m_lpDosHeader;
	IMAGE_NT_HEADERS32* m_lpNtHeader;
	IMAGE_SECTION_HEADER* m_lpSectionHeader;
	DWORD m_dwReadFlag;
	CPeExportManager* m_lpExportManager;
	CPeImportManager* m_lpImportManager;
	CPeResourceManager* m_lpResourceManager;
	CPeExceptionManager* m_lpExceptionManager;
	CPeSecurityManager* m_lpSecurityManager;
	CPeBaseRelocationManager* m_lpBaseRelocationManager;
	CPeDebugManager* m_lpDebugManager;
	CPeTLSManager* m_lpTLSManager;
	CPeLoadConfigManager* m_lpLoadConfigManager;
	CPeBoundImportManager* m_lpBoundImportManager;
	CPeDelayImportManager* m_lpDelayImportManager;
};

#endif