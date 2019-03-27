#include "PolyStub.h"
#include <ctime>
#include <algorithm>



PolyStub::PolyStub(unsigned long Dst)
{
	srand(time(NULL));
	Address = Dst;
}



void PolyStub::GenOPRegImm(unsigned char OP, unsigned long Reg, unsigned long Imm, unsigned char bit8) // check for mov and test
{
	if (rand() % 2 || Recurse == RecurseLevel || Reg == REG::ESP)			// If Recurse is equal to RecurseLevel, Do normal encoding to prevent extreme bloating of code and reset Recurse.
	{
		if (OP == OP::MOV)
		{
			*(unsigned char*)(Address + StubLen) = 0xC7 - bit8;		// Remove last bit in opcode to indicate 8bit operands
			*(unsigned char*)(Address + 1 + StubLen) = 0xC0 | Reg;
		}
		else if (OP == OP::TEST)
		{
			*(unsigned char*)(Address + StubLen) = 0xF7 - bit8;		// Remove last bit in opcode to indicate 8bit operands
			*(unsigned char*)(Address + 1 + StubLen) = 0xC0 | Reg;
		}
		else
		{
			*(unsigned char*)(Address + StubLen) = 0x81 - bit8;		// Remove last bit in opcode to indicate 8bit operands
			*(unsigned char*)(Address + 1 + StubLen) = 0xC0 + (OP * 8) | Reg;
		}

		*(unsigned long*)(Address + 2 + StubLen) = Imm;
		StubLen += 6;

		if (bit8)			// If it is 8bit operands,
			StubLen -= 3;	// remove the last three bytes of the dword to make it a byte.
		Recurse = 0;		// Reset Recurse.
	}
	else		// This would not work if Reg is ESP
	{
		unsigned char RandReg = GetRandReg(Reg);
		GenOPReg(OP1::PUSH, RandReg, 0);
		GenOPRegImm(OP::MOV, RandReg, Imm, bit8);
		GenOPRegReg(OP, Reg, RandReg, bit8);
		GenOPReg(OP1::POP, RandReg, 0);
		++Recurse;
	}
}

void PolyStub::GenOPRegReg(unsigned char OP, unsigned long Reg1, unsigned long Reg2, unsigned char bit8)
{
	if (rand() % 2 && OP != OP::TEST)
	{
		*(unsigned char*)(Address + StubLen) = ((OP * 8) + 3) ^ bit8;		// Zero out first byte in opcode to indicate 8bit
		*(unsigned char*)(Address + 1 + StubLen) = 0xC0 | (Reg1 << 3) | Reg2;	// Place first REG 3 bytes in and REG2 in first 3 bytes
		StubLen += 2;
	}
	else
	{
		if (OP == OP::TEST)
			*(unsigned char*)(Address + StubLen) = 0x85 ^ bit8;
		else
			*(unsigned char*)(Address + StubLen) = ((OP * 8) + 1) ^ bit8;
		*(unsigned char*)(Address + 1 + StubLen) = 0xC0 | (Reg2 << 3) | Reg1;
		StubLen += 2;
	}
	Recurse = 0;		// Reset Recurse.
}

void PolyStub::GenOPRegMem(unsigned char OP, unsigned char Reg, unsigned char Reg2, unsigned long Disp, unsigned char bit8)		// TEST can not be encoded this way around, change operand position and encode.
{
	if (true)
	{
		if (OP == OP::LEA)
		{
			GenOPRegImm(OP::MOV, Reg, Disp, 0);			// Cant be 8 bit operands
			GenOPRegReg(OP::ADD, Reg, Reg2, 0);
		}
		else
		{
			*(unsigned char*)(Address + StubLen) = ((OP * 8) + 3) ^ bit8;
			*(unsigned char*)(Address + StubLen + 1) |= (Reg << 3);		// *(unsigned char*)(Address + StubLen + 1) is modrm byte
			*(unsigned char*)(Address + StubLen + 1) |= Reg2;
			*(unsigned char*)(Address + StubLen + 1) |= (2 << 6);
			if (Reg2 == REG::ESP)
			{
				*(unsigned char*)(Address + StubLen + 2) |= 0x24;
				StubLen += 1;
			}
			*(unsigned long*)(Address + StubLen + 2) = Disp;
			StubLen += 6;
			Recurse = 0;		// Reset Recurse.
		}
	}
}

void PolyStub::GenOPMemReg(unsigned char OP, unsigned char Reg, unsigned long Disp, unsigned char Reg2, unsigned char bit8)
{
	if (true)
		GenOPRegMem(OP, Reg2, Reg, Disp, 2 + bit8);		// Add 0b10 = 2d to bit8 field to zero out the second byte of OP. This indicates that REG field will be added to R/M field.
	
}

/*
	Making my life easier by assembling a variant of the Mem, Imm operands.
*/
void PolyStub::GenOPMemImm(unsigned char OP, unsigned char Reg, unsigned long Imm, unsigned long Disp, unsigned char bit8)
{
	unsigned char RandReg = GetRandReg(Reg);
	GenOPReg(OP1::PUSH, RandReg, 0);
	GenOPRegImm(OP::MOV, RandReg, Imm, bit8);
	GenOPMemReg(OP, Reg, Disp, RandReg, bit8);
	GenOPReg(OP1::POP, RandReg, 0);
	++Recurse;
}

/*
	The one operand instructions are tricky to encode in a single function (I don't want a bloated source with a humongous amount of functions).
	I chose to encode instructions with opcode 0xF7 (NOT, NEG, MUL, IMUL, DIV, IDIV) 
	and 0xFF (INC, DEC, CALL, JMP, PUSH) and 0x8F (POP). 
	The instructions with opcode 0xFF and 0x8F is indicated with an maligned OP of 10.
	When the function finds one of these, it recurse calls itself while fixing the new opcode and aligning OP to correct val.
*/
void PolyStub::GenOPReg(unsigned char OP, unsigned char Reg, unsigned char bit8)
{
	StackVal += OP == OP1::PUSH ? 1 : 0;			// If PUSH, increment stackval.
	StackVal -= OP == OP1::POP ? 1 : 0;				// if POP, decrement stackval.
	if (OP == OP1::PUSH && Recurse < RecurseLevel && rand() % 2)
	{
		GenOPRegImm(OP::SUB, REG::ESP, 4, 0);
		GenOPMemReg(OP::MOV, REG::ESP, 0, Reg, 0);
		++Recurse;
		return;	
	}

	if (OP == OP1::POP)
	{
		if (rand() % 2 || Recurse == RecurseLevel)
			GenOPReg(0, Reg, 0x78 + bit8);				// For POP Reg. (0x8F (0xC0 | Reg)) Mask OP in call with bit8 to 0x8F. (0xF7 ^ 0x78 = 0x8F)
		else
		{
			GenOPRegMem(OP::MOV, Reg, REG::ESP, 0, 0);
			GenOPRegImm(OP::ADD, REG::ESP, 4, 0);
			++Recurse;
		}
	}	
	else if (OP >= 10)
		GenOPReg(OP - 10, Reg, 0x8 + bit8);			// Recursive Gen call with Aligned OP value and bit8 parameter will add 0x8 to 0xF7 (for instructions with opcode 0xFF).
	else
	{		
		*(unsigned char*)(Address + StubLen) = 0xF7 ^ bit8;
		*(unsigned char*)(Address + StubLen + 1) = 0xC0 | (OP * 8) | Reg;
		StubLen += 2;
		Recurse = 0;		// Reset Recurse.
	}
}

void PolyStub::GenOPMem(unsigned char OP, unsigned char Reg, unsigned long Disp, unsigned char bit8) 
{
	StackVal += OP == OP1::PUSH ? 1 : 0;			// If PUSH, increment stackval.
	StackVal -= OP == OP1::POP ? 1 : 0;				// if POP, decrement stackval.
	if (OP == OP1::PUSH && Recurse < RecurseLevel && rand() % 2)
	{
		unsigned char RandReg = GetRandReg(Reg);
		GenOPRegImm(OP::SUB, REG::ESP, 4, 0);
		GenOPReg(OP1::PUSH, RandReg, 0);
		GenOPRegMem(OP::MOV, RandReg, Reg, Disp, bit8);
		GenOPMemReg(OP::MOV, REG::ESP, 4 + StackVal * 4, RandReg, bit8);		// + StackVal*4 because of the stack misalignment of previous PUSHes.
		GenOPReg(OP1::POP, RandReg, 0);
		++Recurse;
		return;
	}

	if (OP == OP1::POP)
	{
		if (rand() % 2 || Recurse == RecurseLevel)
			GenOPMem(0, Reg, Disp, 0x78 + bit8);				// For POP Reg. (0x8F (0xC0 | Reg)) Mask OP in call with bit8 to 0x8F. (0xF7 ^ 0x9F = 0x8F)
		else
		{
			unsigned char RandReg = GetRandReg(Reg);
			GenOPReg(OP1::PUSH, RandReg, 0);
			GenOPRegMem(OP::MOV, RandReg, REG::ESP, 4 + StackVal * 4, bit8);
			GenOPMemReg(OP::MOV, Reg, Disp, RandReg, bit8);
			GenOPReg(OP1::POP, RandReg, 0);
			GenOPRegImm(OP::ADD, REG::ESP, 4, 0);
		}
	}
	else if (OP >= 10)
		GenOPMem(OP - 10, Reg, Disp, 0x8 + bit8);			// Recursive Gen call with Aligned OP value and bit8 parameter will add 0x8 to 0xF7 (for instructions with opcode 0xFF).
	else
	{
		*(unsigned char*)(Address + StubLen) = 0xF7 ^ bit8;
		*(unsigned char*)(Address + StubLen + 1) = 0x80 | (OP * 8) | Reg;
		*(unsigned long*)(Address + StubLen + 2) = Disp;
		StubLen += 6;
	}
}

void PolyStub::GenOPImm(unsigned char OP, unsigned long Imm)
{
	StackVal += OP == OP1::PUSH ? 1 : (OP == OP1::POP ? -1 : 0);			// If PUSH, increment stackval. If POP, decrement stackval.
	if (OP == OP1::PUSH)
	{
		if (rand() % 2 || Recurse == RecurseLevel)
		{
			OP = ReverseByte(OP);		// Reverse 0x16 -> 0x68
			*(unsigned char*)(Address + StubLen) = 0x68;
			*(unsigned long*)(Address + StubLen + 1) = Imm;
			StubLen += 5;
			Recurse = 0;
		}
		else
		{
			GenOPRegImm(OP::SUB, REG::ESP, 4, 0);
			GenOPMemImm(OP::MOV, REG::ESP, Imm, 4, 0);
			++Recurse;
		}
	}
	else if (OP == OP1::RET)
	{
		*(unsigned char*)(Address + StubLen) = OP;
		*(unsigned short*)(Address + StubLen + 1) = Imm;
		StubLen += 3;
		return;
	}
}

/*
	Save all data as relative addresses (StubLen) to base (Address).
	If the data has been tried to be accessed before allocated, it will scan through access list to find the correct address
	of the instruction that has accessed it. It will replace the IMM mark (0xAABBCCDD) with the correct RVA to the allocated data.
*/
void PolyStub::GenData(void* Value, unsigned long Size, const char* DataRef)		
{
Search:
	unsigned long DataAccessAddress = GetListAddress(DataAccessList, DataRef);
	if (DataAccessAddress != -1)						// Check DataRef has been accessed by previous code.
	{
		int ptr = 0;
		while (++ptr)
		{
			if (*(unsigned long*)(DataAccessAddress + ptr) == 0xAABBCCDD)
			{
				*(unsigned long*)(DataAccessAddress + ptr) = StubLen - 5;	// Remove 5 from Address to get Relative from base.
				DataAccessList.erase(std::remove_if(DataAccessList.begin(), DataAccessList.end(), [&](lbl const& v) { return (strcmp(v.Name, DataRef) ? false : true && v.Address == DataAccessAddress); }),
					DataAccessList.end());						// Remove the specific element and carry on searching for other references to the Data
				goto Search;
			}
		}
	}
	
	lbl Data = { DataRef, StubLen };
	DataList.push_back(Data);
	memcpy((void*)(Address + StubLen), Value, Size);
	StubLen += Size;
}

void PolyStub::GenOP(unsigned char OP)
{
	*(unsigned char*)(Address + StubLen) = 0xA0 + OP;
	StubLen += 1;
}

void PolyStub::GenPrefix(unsigned char Prefix)
{
	*(unsigned char*)(Address + StubLen) = Prefix;
	StubLen += 1;
}

unsigned long PolyStub::GetDataAddress(const char* DataRef)
{
	lbl DataAccess = { DataRef, Address + StubLen };
	DataAccessList.push_back(DataAccess);
	if (GetListAddress(DataList, DataRef) != -1)
		return GetListAddress(DataList, DataRef) - 5;	// Remove 5 from Address to get Relative from base.
	return 0xAABBCCDD;		// Mark the data to be replaced
}


/*
	When a Jcc is created we check the LabelList for a corresponding label. If it is found, then it is a label with an address less than the current.
	If it is not found, we allocate a byte to store the Relative jump for later.
*/
void PolyStub::GenJcc(unsigned char OP, const char* Label)
{
	lbl Jcc = { Label, Address + StubLen };
	if (OP == JCC::JMP || OP == JCC::CALL)
	{
		*(unsigned char*)(Address + StubLen) = OP;
		*(unsigned long*)(Address + StubLen + 1) = GetListAddress(Labels, Label) - Jcc.Address - 5;
		StubLen += 5;
	}
	else
	{		
		*(unsigned char*)(Address + StubLen) = 0x70 + OP;
		*(unsigned char*)(Address + StubLen + 1) = GetListAddress(Labels, Label) - Jcc.Address - 2;
		StubLen += 2;
	}
	Jccs.push_back(Jcc);
}

/*
	When we create a label, we have to check for a corresponding Jcc. If found, then we calculate relative address to the current address from the Jcc.
	If not found, we carry on assembling the rest of the instructions until we find a Jcc which points to the label.
*/
void PolyStub::Label(const char* lblName)
{	
	unsigned long JccAddress = GetListAddress(Jccs, lblName);
	if (JccAddress != -1)
		if (*(unsigned char*)(JccAddress) == 0xE9 || *(unsigned char*)(JccAddress) == 0xE8)		// Check for Rel32 OPs.
			*(unsigned long*)(JccAddress + 1) = Address + StubLen - JccAddress - 5;
		else
			*(unsigned char*)(JccAddress + 1) = Address + StubLen - JccAddress - 2;

	lbl label = { lblName, Address + StubLen };
	Labels.push_back(label);
}



unsigned long PolyStub::GetListAddress(std::vector<lbl>List, const char* Label)
{
	for (auto lblStruct : List)
	{
		if (!strcmp(lblStruct.Name, Label))
			return lblStruct.Address;
	}
	return -1;
}


int PolyStub::GetStubLen()
{
	return StubLen;
}