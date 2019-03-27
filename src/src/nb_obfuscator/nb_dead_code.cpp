#include "nb_dead_code.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <xbyak/xbyak/xbyak.h>
#include "nb_obfuscator.h"

class Code : public Xbyak::CodeGenerator {
public:
  Code(){
#if defined(_M_IX86)
    Xbyak::Reg32 rrr = GetRandomRegister();
#elif (defined(_M_X64) || defined(__IA64__))
    Xbyak::Reg64 rrr = GetRandomRegister();
#endif
    push(rrr);
    mov(rrr, RandomInInterval1(0, USHRT_MAX));
    add(rrr, RandomInInterval1(0, USHRT_MAX));
    sub(rrr, RandomInInterval1(0, USHRT_MAX));
    mov(rrr, RandomInInterval1(0, USHRT_MAX));
    add(rrr, RandomInInterval1(0, USHRT_MAX));
    pop(rrr);
  }
private:
#if defined(_M_IX86)
  Xbyak::Reg32 GetRandomRegister() {
    int index = RandomInInterval(Xbyak::Reg32::Code::EAX, Xbyak::Reg32::Code::EDI);
    switch (index)
    {
    case Xbyak::Reg32::Code::EAX:
      return eax;
    case Xbyak::Reg32::Code::ECX:
      return ecx;
    case Xbyak::Reg32::Code::EDX:
      return edx;
    case Xbyak::Reg32::Code::EBX:
      return ebx;
    case Xbyak::Reg32::Code::ESP:
      return GetRandomRegister();
    case Xbyak::Reg32::Code::EBP:
      return GetRandomRegister();
    case Xbyak::Reg32::Code::ESI:
      return esi;
    case Xbyak::Reg32::Code::EDI:
      return edi;
    default:
      break;
    }
    return eax;
#elif (defined(_M_X64) || defined(__IA64__))
  Xbyak::Reg64 GetRandomRegister() {
    int index = RandomInInterval(Xbyak::Reg32::Code::RAX, Xbyak::Reg32::Code::R15);
    switch (index)
    {
    case Xbyak::Reg64::Code::RAX:
      return rax;
    case Xbyak::Reg64::Code::RCX:
      return rcx;
    case Xbyak::Reg64::Code::RDX:
      return rdx;
    case Xbyak::Reg64::Code::RBX:
      return rbx;
    case Xbyak::Reg64::Code::RSP:
      return GetRandomRegister();
    case Xbyak::Reg64::Code::RBP:
      return GetRandomRegister();
    case Xbyak::Reg64::Code::RSI:
      return rsi;
    case Xbyak::Reg64::Code::RDI:
      return rdi;
    case Xbyak::Reg64::Code::R8:
      return r8;
    case Xbyak::Reg64::Code::R9:
      return r9;
    case Xbyak::Reg64::Code::R10:
      return r10;
    case Xbyak::Reg64::Code::R11:
      return r11;
    case Xbyak::Reg64::Code::R12:
      return r12;
    case Xbyak::Reg64::Code::R13:
      return r13;
    case Xbyak::Reg64::Code::R14:
      return r14;
    case Xbyak::Reg64::Code::R15:
      return r15;
    default:
      break;
  }
    return rax;
#endif
  }
};

void MakePoly(std::vector<unsigned char>& out_poly){
  std::vector<unsigned char> poly_buff;
  poly_buff.resize(1000);
  Code code;
  code.getCode();
  out_poly.resize(code.getSize());
  memcpy((PVOID)out_poly.data(), code.getCode(), code.getSize());
}

