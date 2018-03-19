// PEPack.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include "PeFile.h"
#include <iostream>
#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

class  CPEContorl
{
public:
	CPEContorl(){}
	~CPEContorl(){}

	BOOL Init(TCHAR *InputFile);


	BOOL SetEntrySectionSize(DWORD dwAddSize) { return SetNewSectionSize(m_dwEntrySec, dwAddSize); }

	BOOL SetNewSectionSize(DWORD dwNumSec, DWORD dwAddSize);

	BOOL SetNewEntryPointer(DWORD dwEntry, DWORD &dwOldEntry);

	VOID FlushBuffer2File();

	CPeFile m_PEInputFile;

protected:

private:
	IMAGE_DOS_HEADER *m_lpDosHeader;
	IMAGE_NT_HEADERS32 *m_lpNtHeader32;
	DWORD  m_dwEntrySec;

	TCHAR m_inFileName[MAX_PATH*2], m_outFileName[MAX_PATH*2];


	//输出的PE文件

	IMAGE_SECTION_HEADER *m_pSecHeader;

	PVOID  m_pBufferOut;
	HANDLE m_FileHandleOut;
};


BOOL CPEContorl::Init(TCHAR *InputFile)
{
	BOOL bRet  = FALSE;

	if (InputFile == NULL)
	{
		return bRet;
	}

	GetModuleFileName(NULL, m_inFileName, MAX_PATH - 1);
	PathRemoveFileSpec(m_inFileName);
	PathAppend(m_inFileName, InputFile);

	if (m_PEInputFile.Attach(m_inFileName) != IMAGE_NT_SIGNATURE)
	{
//		std::cout << "incorrect windows executive file" << std::endl;
		return FALSE;
	}

	//Dos Header
	const IMAGE_DOS_HEADER* lpDosHeader = m_PEInputFile.GetDosHeader();

	//NT Header
	const IMAGE_NT_HEADERS32* lpNtHeader32 = m_PEInputFile.GetNtHeader();
	//	const IMAGE_NT_HEADERS64* lpNtHeader64 = (IMAGE_NT_HEADERS64*)lpNtHeader32;
	BOOL b64Bit = m_PEInputFile.Is64Bit();

	if (b64Bit)
	{
//		std::cout << "win64 pe file is not supposed" << std::endl;
		m_PEInputFile.Detach();
		return FALSE;
	}

	DWORD dwEntryAddr = lpNtHeader32->OptionalHeader.AddressOfEntryPoint;
	//Section Header
	WORD wSectionNum;
	IMAGE_SECTION_HEADER* lpSectionHeader = (IMAGE_SECTION_HEADER*)m_PEInputFile.GetSectionHeader(&wSectionNum);
	for (WORD i = 0; i < wSectionNum; ++i)
	{
		IMAGE_SECTION_HEADER* pSec = &lpSectionHeader[i];
		if ( (dwEntryAddr >= pSec->VirtualAddress) && (dwEntryAddr < (pSec->VirtualAddress + pSec->Misc.VirtualSize))) 
		{
			m_dwEntrySec = i;
			break;
		}
	}
#pragma warning(push)
#pragma warning(disable: 4996)
	_tcscpy(m_outFileName, m_inFileName);
	_tcscat(m_outFileName, _TEXT(".out"));
#pragma warning(pop)

	HANDLE hFile = CreateFile(m_outFileName, GENERIC_READ, 0, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{

	}

	HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
	LPVOID pMapViewFile = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);


	return bRet;
}


BOOL CPEContorl::SetNewSectionSize(DWORD dwNumSec, DWORD dwAddSize)
{

}



__declspec(naked) void* stubcode()
{
	_asm
	{
		push ebp
		xor ecx,ecx
		mov esi,fs:0x30
		mov esi, [esi + 0x0C];
		mov esi, [esi + 0x1C];
next_module:
		mov ebp, [esi + 0x08];
		mov edi, [esi + 0x20];
		mov esi, [esi];
		cmp [edi + 12*2],cl  
		jne next_module
		mov edi,ebp;
		sub esp,100
		mov ebp,esp;
		mov eax,[edi+3ch] //pe header
		mov edx,[edi+eax+78h]
		add edx,edi
		mov ecx,[edx+18h]  //number of functions
		mov ebx,[edx+20h]
		add ebx,edi
search:
		dec ecx
		mov esi,[ebx+ecx*4]
		add esi,edi;
		mov eax,0x50746547
		cmp [esi],eax
		jne search
		mov eax,0x41636f72
		cmp [esi+4],eax
		jne search

		mov ebx,[edx+24h]
		add ebx,edi 
		mov cx,[ebx+ecx*2]
		mov ebx,[edx+1ch]
		add ebx,edi
		mov eax,[ebx+ecx*4]
		add eax,edi
		mov [ebp+76],eax
	}
//	_asm _emit 0xFF
//  _asm _emit 0x15
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc <= 1)
	{
		std::cout << "no executive file param" << std::endl;
	}
	TCHAR* lpszPath = argv[1];

	CPEContorl PECtl;

	PECtl.Init(lpszPath);

	PECtl.SetEntrySectionSize(0x100);



	//导入表
// 	if (!PE.ReadImport())
// 		return -1;
// 	DWORD nImport;
// 	const IMAGE_IMPORT_DESCRIPTOR* lpImport = PE.GetImportDescriptor(&nImport);
// 	if (lpImport)
// 	{
// 		for (DWORD i = 0UL; i < nImport; ++i)
// 		{
// 			//lpImport[i]
// 
// 			DWORD nThunk;
// 			const IMAGE_THUNK_DATA32* lpThunk = PE.GetImportThunkData(i, &nThunk);
// 			for (DWORD j = 0UL; j < nThunk; ++j)
// 			{
// 				//各个Thunk
// 			}
// 		}
// 	}


	//基址重定位表
// 	if (!PE.ReadBaseRelocation())
// 		return -1;
// 	DWORD nRelocation;
// 	const IMAGE_BASE_RELOCATION* const* lpRelocation = PE.GetBaseRelocation(&nRelocation);
// 	if (lpRelocation)
// 	{
// 		for (DWORD i = 0UL; i < nRelocation; ++i)
// 		{
// 			//lpRelocation[i]
// 			DWORD dwAddress = lpRelocation[i]->VirtualAddress;
// 			DWORD nCount;
// 			const WORD* lpItem = PE.GetBaseRelocationBlock(lpRelocation[i], &nCount);
// 			for (DWORD j = 0; j < nCount; ++j)
// 			{
// 				//lpItem[j]
// 			}
// 		}
// 	}


	return 0;
}

