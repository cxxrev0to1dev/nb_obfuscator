#include "includes.h"

DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

PeExplorer::~PeExplorer()
{

	if (pMap != nullptr)
	{
		UnmapViewOfFile(pMap);
		FileSize = -1;
		pMap = nullptr;
	}

	SectionHeaderList.clear();
	pDosHeader = nullptr;
	pNtHeaders = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;
}

// Overloaded Function to map a PE file to memory
bool PeExplorer::Explore(const char* FileName, DWORD ExtraSize)
{
	printf("Mapping PE File...\n");

	int retries = 0;
	HANDLE FileHandle = INVALID_HANDLE_VALUE;

	do
	{
		FileHandle = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (FileHandle == INVALID_HANDLE_VALUE)
		{
			if (GetLastError() == ERROR_SHARING_VIOLATION)
			{
				++retries;
				Sleep(250);
				continue;
			}
			else
				break;
		}
		else
			break;
	} while (retries < 10);

	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		PeExplorer::~PeExplorer();
		printf("File Could Not Be Read. Error: 0x%X\n", GetLastError());
		return false;
	}

	FileSize = GetFileSize(FileHandle, NULL);
	FileSize += ExtraSize;

	HANDLE hMap = CreateFileMapping(FileHandle, NULL, PAGE_READWRITE, 0, FileSize, NULL);
	if (hMap == INVALID_HANDLE_VALUE)
	{
		CloseHandle(FileHandle);
		printf("Could not CreateFileMapping. Error: 0x%X\n", GetLastError());
		std::cin.get();
		return 0;
	}

	pMap = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, FileSize);
	if (pMap == nullptr)
	{
		CloseHandle(FileHandle);
		CloseHandle(hMap);
		printf("Could not Map File. Error: 0x%X\n", GetLastError());
		std::cin.get();
		return 0;
	}

	CloseHandle(FileHandle);
	CloseHandle(hMap);

	if (!Explore(pMap))
	{
		PeExplorer::~PeExplorer();
		return false;
	}

	return true;
}

// Overloaded Function to map a PE file to memory
bool PeExplorer::Explore(PVOID pPe)
{
	printf("Reading PE File...\n");

	pMap = pPe;

	pDosHeader = static_cast<PIMAGE_DOS_HEADER>(pPe);		
	if (!VerifyDosHeader(pDosHeader->e_magic))
	{
		PeExplorer::~PeExplorer();
		printf("Could not verify DOS header\n");
		return false;
	}

	pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((DWORD)pDosHeader + pDosHeader->e_lfanew);		// pDosHeader + sizeof(DosHeader) + sizeof(DosStub) = pNtHeaders. Keep in mind that dos header + stub does not have constant size
	if (!VerifyPeHeader(pNtHeaders->Signature))
	{
		PeExplorer::~PeExplorer();
		printf("Could not verify PE header\n");
		return false;
	}

	pFileHeader = static_cast<PIMAGE_FILE_HEADER>(&pNtHeaders->FileHeader);			// Get FileHeader pointer
	pOptionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER>(&pNtHeaders->OptionalHeader);		// Get OptionalHeader pointer
	
	PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);	// Address of first section header = pOptionalHeader + sizeof(OptionalHeader)
																																				// Keep in mind that OptionalHeader size is not constant use ->SizeOfOptionalHeader
	for (int i = 0; i < pFileHeader->NumberOfSections; ++i)		
		SectionHeaderList.push_back(pFirstSection + i);		// The section headers comes after each other in memory

	return true;
}

// We do not have to relocate anything after the newly added section since there is always enough size for an extra SECTION_HEADER
void PeExplorer::AddNewSection(const char* SectionName, DWORD SectionSize, DWORD Characteristics)
{
	DWORD SectionAlignment = pOptionalHeader->SectionAlignment;

	PIMAGE_SECTION_HEADER LastSection = SectionHeaderList.at(pFileHeader->NumberOfSections - 1);
	IMAGE_SECTION_HEADER NewSection = { 0 };			// Template for new section					
	RtlCopyMemory(&NewSection.Name, SectionName, 8);	// Insert name
	NewSection.Misc.VirtualSize = align(SectionSize, SectionAlignment, 0);		// Calculate virtualsize
	NewSection.VirtualAddress = align(LastSection->Misc.VirtualSize, SectionAlignment, LastSection->VirtualAddress);	// Calculate VirtualAddress
	NewSection.SizeOfRawData = align(SectionSize, pOptionalHeader->FileAlignment, 0);		// Calculate SizeOfRawData
	NewSection.PointerToRawData = align(LastSection->SizeOfRawData, pOptionalHeader->FileAlignment, LastSection->PointerToRawData);	// Calculate PointerToRawData
	NewSection.Characteristics = Characteristics;

	DWORD* dwAddress = (DWORD*)((DWORD)LastSection + sizeof(IMAGE_SECTION_HEADER));		// New SectionHeader will be copied to dwAddress which is end of last SECTION_HEADER
	RtlCopyMemory(dwAddress, &NewSection, sizeof(IMAGE_SECTION_HEADER));			// Copy new section header
	SectionHeaderList.push_back(reinterpret_cast<PIMAGE_SECTION_HEADER>(dwAddress));

	pOptionalHeader->SizeOfImage = reinterpret_cast<PIMAGE_SECTION_HEADER>(dwAddress)->VirtualAddress + reinterpret_cast<PIMAGE_SECTION_HEADER>(dwAddress)->Misc.VirtualSize;	// Update size of image
	pFileHeader->NumberOfSections += 1;		// Increase number of sections
	return;
}


PIMAGE_SECTION_HEADER PeExplorer::GetSectionByName(const char* SectionName)
{
	for (auto Section : SectionHeaderList)
	{
		if (!memcmp(Section->Name, SectionName, strlen(SectionName)))
			return Section;
	}
	return nullptr;
}

PIMAGE_SECTION_HEADER PeExplorer::GetSectionByCharacteristics(DWORD Characteristics)
{
	for (auto Section : SectionHeaderList)
	{
		if (Section->Characteristics & Characteristics)
			return Section;
	}
	return nullptr;
}

PIMAGE_SECTION_HEADER PeExplorer::GetLastSection()
{
	PIMAGE_SECTION_HEADER LastSection = new IMAGE_SECTION_HEADER();
	for (auto Section : SectionHeaderList)
	{
		if (Section->PointerToRawData > LastSection->PointerToRawData)
			LastSection = Section;
	}
	return LastSection;
}

std::vector<PIMAGE_SECTION_HEADER> PeExplorer::GetSectionList()
{
	return SectionHeaderList;
}

PIMAGE_DOS_HEADER PeExplorer::GetDosHeader()
{
	return pDosHeader;
}

PIMAGE_NT_HEADERS PeExplorer::GetNtHeaders()
{
	return pNtHeaders;
}

PIMAGE_FILE_HEADER PeExplorer::GetFileHeader()
{
	return pFileHeader;
}

PIMAGE_OPTIONAL_HEADER PeExplorer::GetOptionalHeader()
{
	return pOptionalHeader;
}