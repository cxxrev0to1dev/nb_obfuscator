#pragma once

/*
	Sources:
	http://www.c-jump.com/CIS77/CPU/x86/lecture.html
	http://www.c-jump.com/CIS77/reference/Instructions_by_Opcode.html
*/

#define ReverseByte(x) ((x * 0x0802LU & 0x22110LU) | (x * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16

#define RecurseLevel 3


enum REG
{
	EAX,
	ECX,
	EDX,
	EBX,
	ESP,
	EBP,
	ESI,
	EDI,
};

enum REG8
{
	AL,
	CL,
	DL,
	BL,
	AH,
	CH,
	DH,
	BH,
};

enum OP
{
	ADD,
	OR,
	ADC,
	SBB,
	AND,
	SUB,
	XOR,
	CMP,
	TEST = 0x10,
	MOV,
	LEA,
};


enum OP1
{
	NOT = 2,
	NEG,
	MUL,
	IMUL,
	DIV,
	IDIV,
	INC = 10,
	DEC,
	CALL,
	JMP = 14,
	PUSH = 16,
	POP,
	RET = 0xC2,
};

namespace JCC
{
	enum JCC
	{
		JO,
		JNO,
		JB,
		JC = 2,
		JNAE = 2,
		JAE,
		JNB = 3,
		JNC = 3,
		JE,
		JZ = 4,
		JNE,
		JNZ = 5,
		JBE,
		JNA = 6,
		JA,
		JNBE = 7,
		JS,
		JNS,
		JP,
		JPE = 0xA,
		JNP,
		JPO = 0xB,
		JL,
		JNGE = 0xC,
		JNL,
		JGE = 0xD,
		JLE,
		JNG = 0xE,
		JG,
		JNLE = 0xF,
		CALL = 0xE8,	
		JMP,			
	};
}

enum PREFIX
{
	ES = 0x26,
	CS = 0x2E,
	SS = 0x36,
	DS = 0x3E,
	FS = 0x64,
	GS,
	OperandOverride,
	AddressOverride,
	LOCK = 0xF0,
	REPNE = 0xF2,
	REPNZ = 0xF2,
	REP,
	REPE = 0xF3,
};

enum StrMan
{
	movsb = 4,
	movsd,
	cmpsb,
	cmpsd,
	stosb = 10,
	stosd,
	lodsb,
	lodsd,
	scasb,
	scasd,
};



typedef struct _lbl
{
	const char* Name;
	DWORD Address;
}lbl;

class PolyStub
{
public:
	PolyStub(DWORD Dst);
	
	
	void GenOPRegImm(BYTE OP, DWORD Reg, DWORD Imm, BYTE bit8);				// Generates OP Reg, Imm	(ex. AND ebx, 0x10)
	void GenOPRegReg(BYTE OP, DWORD Reg1, DWORD Reg2, BYTE bit8);			// Generates OP Reg, Reg	(ex. MOV eax, ecx)

	void GenOPRegMem(BYTE OP, BYTE Reg, BYTE Reg2, DWORD Disp, BYTE bit8);	// Generates OP Reg, Mem	(ex. XOR eax, dword ptr[esp])
	void GenOPRegMem(BYTE OP, BYTE Reg, char* DataRef, BYTE bit8)
	{
		GenOPRegMem(OP, Reg, REG::EBP, GetDataAddress(DataRef), bit8);
	}

	void GenOPMemReg(BYTE OP, BYTE Reg, DWORD Disp, BYTE Reg2, BYTE bit8);	// Generates OP Mem, Reg	(ex. SUB byte ptr[eax + 0x1000], ecx)
	void GenOPMemReg(BYTE OP, char* DataRef, BYTE Reg, BYTE bit8)
	{
		GenOPMemReg(OP, REG::EBP, GetDataAddress(DataRef), Reg, bit8);
	}

	void GenOPMemImm(BYTE OP, BYTE Reg, DWORD Imm, DWORD Disp, BYTE bit8);	// Generates OP Mem, Imm	(ex. ADD dword ptr[eax + 0x10], 0x10)
	void GenOPMemImm(BYTE OP, char* DataRef, DWORD Imm, BYTE bit8)
	{
		GenOPMemImm(OP, REG::EBP, Imm, GetDataAddress(DataRef), bit8);
	}
	void GenOPReg(BYTE OP, BYTE Reg, BYTE bit8);							// Generates OP Reg			(ex. PUSH eax)

	void GenOPMem(BYTE OP, BYTE Reg, DWORD Disp, BYTE bit8);				// Generates OP Mem			(ex. POP dword ptr[eax])
	void GenOPMem(BYTE OP, char* DataRef, BYTE bit8)
	{
		GenOPMem(OP, REG::EBP, GetDataAddress(DataRef), bit8);
	}

	void GenJcc(BYTE OP, const char* Label);								// Generates Jcc Label		(ex. JMP L1)
	void GenOPImm(BYTE OP, DWORD Imm);										// Generates OP Imm			(ex. RET 3)
	void GenOP(BYTE OP);													// Generates OP				(ex. cmpsb)					
	void GenData(void* Value, DWORD Size, const char* DataRef);				// Generates Data			(ex. dd 0)
	void GenPrefix(BYTE Prefix);											// Generates Prefix			(ex. FS:)

	void Label(const char* lblName);										// Generates Labels			(ex. L1:)

	int GetStubLen();
	
			
private:
	DWORD GetListAddress(std::vector<lbl>List, const char* Label);
	DWORD GetDataAddress(const char* DataRef);
	
	BYTE GetRandReg(BYTE Reg1)
	{
		while (true)
		{
			BYTE Reg = rand() % 7;
			if (Reg == Reg1 || Reg == REG::ESP || Reg == REG::EBP)
				continue;
			return Reg;
		}
	}

	DWORD Address;
	DWORD StubLen = 0;
	DWORD Recurse = 0;
	DWORD StackVal = 0;

	std::vector<lbl>Labels;
	std::vector<lbl>Jccs;

	std::vector<lbl>DataList;
	std::vector<lbl>DataAccessList;
};

