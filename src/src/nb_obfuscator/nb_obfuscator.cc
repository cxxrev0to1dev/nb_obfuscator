#include "nb_obfuscator.h"
#include <cstdlib>
#include <ctime>
#include <cassert>
#include <random>
#include <fstream>
#if defined(OS_WIN)
#include <Windows.h>
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"capstone.lib")
#if defined(_M_IX86)
typedef std::uint32_t uint;
#elif (defined(_M_X64) || defined(__IA64__))
typedef std::uint64_t uint;
#endif
#endif

#include "base/logging.h"

#ifdef __cplusplus
extern "C" {
#endif
#include <udis86/libudis86/types.h>
#include <udis86/udis86.h>
#include <capstone/include/capstone/platform.h>
#include <capstone/include/capstone/capstone.h>
#ifdef __cplusplus
};
#endif

#include "nb_dead_code.h"

template <typename Type>
void Read(const Type* str, std::vector<unsigned char>& data) {
  std::ifstream infile(str, std::ifstream::binary | std::ifstream::in);
  if (!infile.is_open()) {
    data.resize(0);
    return;
  }
  infile.seekg(0, infile.end);
  std::streamoff size = infile.tellg();
  infile.seekg(0);
  data.resize((size_t)size);
  infile.read((char*)&data[0], size);
  infile.close();
  infile.clear();
}
template <typename Type>
void Write(const Type* str, const char* data, size_t len) {
  std::ofstream out(str, std::ofstream::binary | std::ofstream::out);
  out.write(data, len);
  out.flush();
  out.close();
  out.clear();
}
template <typename Type>
void Write(const Type* str, const std::vector<unsigned char>& data) {
  Write<Type>(str, data.data(), data.size());
}
uint alignment(uint size, uint align) {
  if (size%align != 0)
    return  (size / align + 1)*align;
  return size;
}
int RandomInInterval(int min, int max) {
  int intervalLen = max - min + 1;
  int ceilingPowerOf2 = pow(2, ceil(log2(intervalLen)));
  std::random_device r;
  std::default_random_engine e1(r());
  std::uniform_int_distribution<int> uniform_dist(min, max);
  int randomNumber = uniform_dist(e1) % ceilingPowerOf2;
  if (randomNumber < intervalLen) {
    int r = min + randomNumber;
    if (r >= min && r <= max) {
      return r;
    }
  }
  return RandomInInterval(min, max);
}
int RandomInInterval1(int min, int max) {
  int intervalLen = max - min + 1;
  int ceilingPowerOf2 = pow(2, ceil(log2(intervalLen)));
  std::random_device r;
  std::default_random_engine e1(r());
  std::uniform_int_distribution<int> uniform_dist(min, max);
  int randomNumber = uniform_dist(e1) % ceilingPowerOf2;
  int r1 = min + randomNumber;
  if (r1 >= min && r1 <= max) {
    return r1;
  }
  return RandomInInterval(min, max);
}
unsigned char GetRandomRegisterBytes() {
  unsigned char _rand_reg[] = { 0x50, 0x51, 0x52, 0x53, 0x53, 0x54, 0x55, 0x56, 0x57 };
  int index = RandomInInterval(0, 8);
  assert(index <= 9);
  return _rand_reg[index];
}
int GenConfusionCallMem(void * dst, size_t ppa_rva, void * src, size_t code_va_to_raw_offset, size_t imagbase_offset) {
#if defined(_M_IX86)
  //0048E7DF    53              push    ebx                               ; random bytes
  //0048E7E0    C70424 EDE74800 mov     dword ptr[esp], 0048E7ED          ; next instr
  //0048E7E7 - FF25 50704400    jmp     dword ptr[<&KERNEL32.GetCurrent>  ; call func
  //0048E7ED  ^ E9 FE4FF9FF     jmp     004237F0                          ; call func return address
  unsigned long _next_address = 0;
  unsigned char call[] = { 0x50,
                          0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
                          0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                          0xE9, 0x00, 0x00, 0x00, 0x00 };
  unsigned long call_mem_len = sizeof(call);
  unsigned char * pdst = (unsigned char *)dst;
  unsigned char * psrc = (unsigned char *)src;
  unsigned long _next_opcode_va = ((unsigned long)psrc + 5 + code_va_to_raw_offset + imagbase_offset);
  memset(call, GetRandomRegisterBytes(), sizeof(unsigned char));
  memmove(call + 10, psrc + 2, sizeof(unsigned long));

  memset(psrc, 0xE9, sizeof(unsigned char));
  *(unsigned long *)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - _next_opcode_va);

  memset(psrc + 5, 0x90, sizeof(unsigned char));
  _next_address = (unsigned long)((unsigned long)pdst + 14 + ppa_rva + imagbase_offset);
  memmove((void *)(call + 4), (void *)&_next_address, sizeof(unsigned long));
  _next_address = (unsigned long)(_next_opcode_va - ((unsigned long)pdst + 14 + ppa_rva + imagbase_offset + 5));
  memmove((void *)(call + 15), (void *)&_next_address, sizeof(unsigned long));
  memmove(pdst, call, call_mem_len);
#elif (defined(_M_X64) || defined(__IA64__))
  unsigned long _next_address = 0;
  unsigned char call[] = { 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00 };
  unsigned long call_mem_len = sizeof(call);
  unsigned char* pdst = (unsigned char *)dst;
  unsigned char* psrc = (unsigned char *)src;
  unsigned long _next_opcode_va = ((unsigned long)psrc + 5 + code_va_to_raw_offset + imagbase_offset);

  unsigned long call_rva = ((*(unsigned long*)(psrc + 2)) + 6);
  //calc call qword ptr ds:[orig_call_va] 
  unsigned long orig_call_va = ((unsigned long)psrc + call_rva);
  memset(psrc, 0xE9, sizeof(unsigned char));
  *(unsigned long *)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - _next_opcode_va);
  memset(psrc + 5, 0x90, sizeof(unsigned char));
  _next_address = (unsigned long)(_next_opcode_va - ((unsigned long)pdst + 6 + ppa_rva + imagbase_offset + 5));
  //calc call qword ptr ds:[curr_call_va] 
  unsigned long curr_call_va = ((unsigned long)pdst + call_rva);
  call_rva += (orig_call_va - curr_call_va - 6);
  call_rva -= (ppa_rva - code_va_to_raw_offset);
  memmove(call + 2, &call_rva, sizeof(unsigned long));
  memmove((void *)(call + 7), (void *)&_next_address, sizeof(unsigned long));
  memmove(pdst, call, call_mem_len);
#endif
  return call_mem_len;
}

int GenConfusionCallRVA(void * dst, size_t ppa_rva, void * src, size_t code_va_to_raw_offset, uint imagbase_offset) {
  //0048E634    53              push    ebx                              ; random bytes
  //0048E635    C70424 41E64800 mov     dword ptr [esp], 0048E641        ; next instr
  //0048E63C  ^ E9 195EF9FF     jmp     0042445A                         ; call func
  //0048E641  ^ E9 E44EF9FF     jmp     0042352A                         ; call func return address
#if defined(_M_IX86)
  unsigned char call[] = { 0x50,
                        0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
                        0xE9, 0x00, 0x00, 0x00, 0x00,
                        0xE9, 0x00, 0x00, 0x00, 0x00
  };
  unsigned long call_func_rva_len = sizeof(call);
  unsigned char * pdst = (unsigned char *)dst;
  unsigned char * psrc = (unsigned char *)src;
  unsigned long _next_opcode_va = ((unsigned long)psrc + 5 + code_va_to_raw_offset + imagbase_offset);
  unsigned long _jmp_va = ((unsigned long)psrc + (*(unsigned long*)(psrc + 1)) + 6 + code_va_to_raw_offset + imagbase_offset);

  memset(psrc, 0xE9, sizeof(unsigned char));
  *(unsigned long *)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - _next_opcode_va);
  memset(call, GetRandomRegisterBytes(), sizeof(unsigned char));
  unsigned long _ret_address = (unsigned long)((unsigned long)pdst + 13 + ppa_rva + imagbase_offset);
  memmove((void *)(call + 4), (void *)&_ret_address, sizeof(unsigned long));
  _jmp_va -= ((unsigned long)pdst + 9 + ppa_rva + imagbase_offset + 5);
  memmove((void *)(call + 9), (void *)&_jmp_va, sizeof(unsigned long));
  *(unsigned long *)(call + 14) = (_next_opcode_va - ((unsigned long)pdst + 13 + ppa_rva + imagbase_offset + 5));
  memmove(pdst, call, call_func_rva_len);
#elif (defined(_M_X64) || defined(__IA64__))
  unsigned char * pdst = (unsigned char *)dst;
  unsigned char * psrc = (unsigned char *)src;
  unsigned long next_instr_va = ((unsigned long)psrc + 5 + code_va_to_raw_offset + imagbase_offset);
  unsigned long _jmp_va = ((unsigned long)psrc + (*(unsigned long*)(psrc + 1)) + 6 + code_va_to_raw_offset + imagbase_offset);
  memset(psrc, 0xE9, sizeof(unsigned char));
  *(unsigned long*)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - next_instr_va);
  _jmp_va -= ((unsigned long)pdst + 1 + ppa_rva + imagbase_offset + 5);
  //////////////////////////////////////////////////////////////////////////
  unsigned char call_func[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
  unsigned long call_func_rva_len = sizeof(call_func);
  memmove((void *)(call_func + 1), (void *)&_jmp_va, sizeof(unsigned long));
  memmove(pdst, call_func, call_func_rva_len);
  //////////////////////////////////////////////////////////////////////////
  std::vector<unsigned char> poly_code;
  MakePoly(poly_code);
  memmove(pdst + call_func_rva_len, poly_code.data(), poly_code.size());
  call_func_rva_len += poly_code.size();
  next_instr_va += poly_code.size();
  //////////////////////////////////////////////////////////////////////////
  unsigned char jmp_call_next_instr[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
  unsigned long jmp_call_next_instr_len = sizeof(jmp_call_next_instr);
  *(unsigned long *)(jmp_call_next_instr + 1) = (next_instr_va - ((unsigned long)pdst + call_func_rva_len + ppa_rva + imagbase_offset + call_func_rva_len));
  memmove(pdst + call_func_rva_len, jmp_call_next_instr, jmp_call_next_instr_len);
  call_func_rva_len += jmp_call_next_instr_len;
#endif
  return call_func_rva_len;
}
int GenConfusionCopyInstrJmpReturn(void * dst, size_t ppa_rva, void * src, int instr_size, size_t code_va_to_raw_offset, uint imagbase_offset) {
  unsigned char * pdst = (unsigned char *)dst;
  unsigned char * psrc = (unsigned char *)src;
  std::vector<unsigned char> psrc_data;
  psrc_data.resize(instr_size);
  memmove(psrc_data.data(), psrc, instr_size);
  unsigned long next_instr_va = ((unsigned long)psrc + 5 + code_va_to_raw_offset + imagbase_offset);
  //////////////////////////////////////////////////////////////////////////
  memset(psrc, 0xE9, sizeof(unsigned char));
  *(unsigned long *)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - next_instr_va);
  memset(psrc + 5, 0x90, (instr_size - 5));
  //////////////////////////////////////////////////////////////////////////
  memmove(pdst, psrc_data.data(), instr_size);
  //////////////////////////////////////////////////////////////////////////
  unsigned char jmp_call_next_instr[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
  unsigned long jmp_call_next_instr_len = sizeof(jmp_call_next_instr);
  next_instr_va -= instr_size;
  next_instr_va -= jmp_call_next_instr_len;
  *(unsigned long *)(&jmp_call_next_instr[1]) = (next_instr_va - ((unsigned long)pdst + ppa_rva + imagbase_offset));
  memmove(pdst + instr_size, jmp_call_next_instr, jmp_call_next_instr_len);
  //////////////////////////////////////////////////////////////////////////
  return (jmp_call_next_instr_len + instr_size);
}
int GenConfusionPushImm(void * dst, size_t ppa_rva, void * src, int instr_size, size_t code_va_to_raw_offset, size_t imagbase_offset, bool is_copy) {
  if (!is_copy) {
    //0048E96C    54              push    esp
    //0048E96D    C70424 79E94800 mov     dword ptr[esp], 0048E979
    //0048E974  ^ E9 2C4AFAFF     jmp     004333A5
    unsigned char push[] = { 0x50,
                            0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
                            0xE9, 0x00, 0x00, 0x00, 0x00 };
    unsigned long push_len = sizeof(push);
    unsigned char * pdst = (unsigned char *)dst;
    unsigned char * psrc = (unsigned char *)src;
    unsigned long _next_opcode_va = ((unsigned long)psrc + instr_size + code_va_to_raw_offset + imagbase_offset);
    memmove(push + 4, psrc + 1, sizeof(unsigned long));
    memset(push, GetRandomRegisterBytes(), sizeof(unsigned char));
    memset(psrc, 0xE9, sizeof(unsigned char));
    *(unsigned long *)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - _next_opcode_va);
    *(unsigned long *)(push + 9) = (_next_opcode_va - ((unsigned long)pdst + 8 + ppa_rva + imagbase_offset + instr_size));
    memmove(pdst, push, push_len);
    return push_len;
  }
  else {
    unsigned char * pdst = (unsigned char *)dst;
    unsigned char * psrc = (unsigned char *)src;
    std::vector<unsigned char> psrc_data;
    psrc_data.resize(instr_size);
    memmove(psrc_data.data(), psrc, instr_size);
    unsigned long next_instr_va = ((unsigned long)psrc + instr_size + code_va_to_raw_offset + imagbase_offset);
    memset(psrc, 0xE9, sizeof(unsigned char));
    *(unsigned long *)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - next_instr_va);
    memset(psrc + 5, 0x90, (instr_size - 5));
    memmove(pdst, psrc_data.data(), instr_size);
    //////////////////////////////////////////////////////////////////////////
    std::vector<unsigned char> poly_code;
    MakePoly(poly_code);
    memmove(pdst + instr_size, poly_code.data(), poly_code.size());
    instr_size += poly_code.size();
    next_instr_va += poly_code.size();
    //////////////////////////////////////////////////////////////////////////
    unsigned char jmp_call_next_instr[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    unsigned long jmp_call_next_instr_len = sizeof(jmp_call_next_instr);
    *(unsigned long *)(jmp_call_next_instr + 1) = (next_instr_va - ((unsigned long)pdst + instr_size + ppa_rva + imagbase_offset + instr_size));
    memmove(pdst + instr_size, jmp_call_next_instr, jmp_call_next_instr_len);
    return (jmp_call_next_instr_len + instr_size);
  }
}
class GenConfusionJCC
{
public:
  GenConfusionJCC(void * dst, size_t ppa_rva, void * src, int instr_size, size_t code_va_to_raw_offset, size_t imagbase_offset) {
    gen_len = 0;
    unsigned char * pdst = (unsigned char *)dst;
    unsigned char * psrc = (unsigned char *)src;
    std::vector<unsigned char> psrc_data;
    psrc_data.resize(instr_size);
    memmove(psrc_data.data(), psrc, instr_size);
    unsigned long next_instr_va = ((unsigned long)psrc + 5 + code_va_to_raw_offset + imagbase_offset);
    //////////////////////////////////////////////////////////////////////////
    memset(psrc, 0xE9, sizeof(unsigned char));
    *(unsigned long *)(psrc + 1) = (unsigned long)(pdst + ppa_rva + imagbase_offset - next_instr_va);
    memset(psrc + 5, 0x90, (instr_size - 5));
    memmove(pdst, psrc_data.data(), instr_size);
    //////////////////////////////////////////////////////////////////////////
    unsigned char jmp_call_next_instr[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    unsigned long jmp_call_next_instr_len = sizeof(jmp_call_next_instr);
    *(unsigned long *)(&jmp_call_next_instr[1]) = (next_instr_va - ((unsigned long)pdst + ppa_rva + imagbase_offset));
    memmove(pdst + instr_size, jmp_call_next_instr, jmp_call_next_instr_len);
    gen_len = (jmp_call_next_instr_len + instr_size);
  }
  const int GetGenLen() const {
    return gen_len;
  }
private:
  int gen_len;
};
unsigned long GenConfusion(const wchar_t * path) {
  std::vector<unsigned char> data;
  Read<wchar_t>(path, data);
  if (data.empty()) {
    return 0;
  }
  std::vector<unsigned char> data_a;
  data_a.resize(data.size() * 5);
  memmove(data_a.data(), data.data(), data.size());
  unsigned char* imagebase = data_a.data();
  PIMAGE_DOS_HEADER dosh = (PIMAGE_DOS_HEADER)imagebase;
  if (dosh->e_magic != IMAGE_DOS_SIGNATURE) {
    return 0;
  }
#if defined(_M_IX86)
  PIMAGE_NT_HEADERS32 nth = (PIMAGE_NT_HEADERS32)&imagebase[dosh->e_lfanew];
  if (nth->Signature != IMAGE_NT_SIGNATURE) {
    return 0;
  }
  PIMAGE_FILE_HEADER fileh = (PIMAGE_FILE_HEADER)&nth->FileHeader;
  PIMAGE_OPTIONAL_HEADER32 opth = (PIMAGE_OPTIONAL_HEADER32)&nth->OptionalHeader;
  PIMAGE_SECTION_HEADER psection = nullptr;
  int opt32_size = sizeof(IMAGE_OPTIONAL_HEADER32);
  int sss = sizeof(std::uintptr_t);
  psection = (PIMAGE_SECTION_HEADER)((std::uint32_t)nth + opt32_size + sizeof(IMAGE_FILE_HEADER) + sss);
#elif (defined(_M_X64) || defined(__IA64__))
  PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)&imagebase[dosh->e_lfanew];
  if (nth->Signature != IMAGE_NT_SIGNATURE) {
    return 0;
  }
  PIMAGE_FILE_HEADER fileh = (PIMAGE_FILE_HEADER)&nth->FileHeader;
  PIMAGE_OPTIONAL_HEADER64 opth = (PIMAGE_OPTIONAL_HEADER64)&nth->OptionalHeader;
  PIMAGE_SECTION_HEADER psection = nullptr;
  int opt64_size = sizeof(IMAGE_OPTIONAL_HEADER64);
  int sss = sizeof(std::uintptr_t);
  psection = (PIMAGE_SECTION_HEADER)((std::uint64_t)nth + opt64_size + sizeof(IMAGE_FILE_HEADER) + sizeof(sss));
#endif
  uint add_code_length = 0;
  uint _min_image_base = opth->ImageBase;
  uint _max_image_base = opth->ImageBase + opth->SizeOfImage;
  uint section_num = fileh->NumberOfSections;
  psection[section_num - 1].Characteristics = 0xE0000080;
  unsigned char* ppa = psection[section_num - 1].PointerToRawData + imagebase;
  uint ppa_rva = psection[section_num - 1].VirtualAddress - psection[section_num - 1].PointerToRawData;
  uint imagbase_offset = (_min_image_base - (uint)imagebase);

  for (uint i = 0; i < section_num - 2; i++) {
    uint _section_raw = psection[i].PointerToRawData;
    uint _section_raw_sze = psection[i].SizeOfRawData;
    uint code_va_to_raw_offset = psection[i].VirtualAddress - _section_raw;
    unsigned char* pcode = (unsigned char *)(imagebase + _section_raw);
    if (!(IMAGE_SCN_MEM_EXECUTE & psection[i].Characteristics)) {
      continue;
    }
#define udis86
#if  defined(capstone)
    csh handle = { 0 };
    cs_err err = cs_open(CS_ARCH_X86, ((fileh->Machine == IMAGE_FILE_MACHINE_I386) ? CS_MODE_32 : CS_MODE_64), &handle);
    if (err) {
      abort();
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    uint64_t address = 0;
    cs_insn *insn;
    //const char ssss[] = { 0x48,0x83,0xEC,0x28,0xE8,0x5B,0x0B,0x00,0x00,0x48,0x83,0xC4,0x28,0xE9,0x72,0xFE,0xFF,0xFF,0xCC };
    //size_t count = cs_disasm(handle, (const uint8_t*)ssss, sizeof(ssss), address, 0, &insn);
    size_t count = cs_disasm(handle, pcode, _section_raw_sze, address, 0, &insn);
    for (uint instr_index = 0; instr_index < count; instr_index++) {
      int dis_len = insn[instr_index].size;
      if ((dis_len == 5 || dis_len == 6) && (!strnicmp(insn[instr_index].mnemonic, "call", 4))) {
        if (insn[instr_index].detail->x86.operands->type == X86_OP_IMM) {
          int gen_len = GenConfusionCallRVA(ppa, ppa_rva, pcode, code_va_to_raw_offset, imagbase_offset);
          ppa += gen_len;
          add_code_length += gen_len;
        }
        else if (insn[instr_index].detail->x86.operands->type == X86_OP_MEM) {
          uint t1 = insn[instr_index].detail->x86.operands->mem.disp + opth->ImageBase;
          if (t1 >= _min_image_base && t1 <= _max_image_base) {
            int gen_len = GenConfusionCallMem(ppa, ppa_rva, pcode, code_va_to_raw_offset, code_mem_offset);
            ppa += gen_len;
            add_code_length += gen_len;
          }
        }
        else {
          __debugbreak();
        }
      }
      else if (dis_len == 5 && (!strnicmp(insn[instr_index].mnemonic, "push", 4))) {
        uint t1 = insn[instr_index].detail->x86.operands->imm + opth->ImageBase;
        if (insn[instr_index].detail->x86.operands->type == X86_OP_IMM) {
          if (t1 >= _min_image_base && t1 <= _max_image_base) {
            int gen_len = GenConfusionPushImm(ppa, ppa_rva, pcode, code_va_to_raw_offset, code_mem_offset);
            ppa += gen_len;
            add_code_length += gen_len;
          }
          else {
            __debugbreak();
          }
        }
      }
      pcode += dis_len;
    }
    cs_free(insn, count);
    insn = nullptr;
    cs_close(&handle);
  }
#elif defined(udis86)
    ud_t ud_obj = { 0 };
    ud_init(&ud_obj);
    ud_set_syntax(&ud_obj, ud_translate_intel);
    ud_set_mode(&ud_obj, ((fileh->Machine == IMAGE_FILE_MACHINE_I386) ? 32 : 64));
    ud_set_input_buffer(&ud_obj, pcode, _section_raw_sze);
    for (uint instr_index = 0; instr_index < _section_raw_sze; instr_index++) {
      int dis_len = ud_disassemble(&ud_obj);
      if (dis_len == 5 && ud_obj.mnemonic == UD_Icall && ud_obj.operand->type == UD_OP_JIMM) {
        uint t1 = ((ud_obj.operand->lval.uqword + (uint)pcode + dis_len) - (uint)imagebase) + opth->ImageBase;
        if ((pcode[0] == 0xE8) && t1 >= _min_image_base && t1 <= _max_image_base) {
          const char* sss = ud_insn_asm(&ud_obj);
          int gen_len = GenConfusionCallRVA(ppa, ppa_rva, pcode, code_va_to_raw_offset, imagbase_offset);
          ppa += gen_len;
          add_code_length += gen_len;
        }
        else if (((uint)pcode - (uint)imagebase) <= 0xFFFFFF) {
          const char* sss = ud_insn_asm(&ud_obj);
          int gen_len = GenConfusionCallRVA(ppa, ppa_rva, pcode, code_va_to_raw_offset, imagbase_offset);
          ppa += gen_len;
          add_code_length += gen_len;
        }
        else {
#ifdef _DEBUG
          __debugbreak();
#endif
        }
      }
      else if (dis_len == 6 && ud_obj.mnemonic == UD_Icall && ud_obj.operand->type == UD_OP_MEM) {
        uint t1 = ud_obj.operand->lval.udword + opth->ImageBase;
        if ((pcode[0] == 0xff && pcode[1] == 0x15) && t1 >= _min_image_base && t1 <= _max_image_base) {
          int gen_len = GenConfusionCallMem(ppa, ppa_rva, pcode, code_va_to_raw_offset, imagbase_offset);
          ppa += gen_len;
          add_code_length += gen_len;
        }
        else if ((fileh->Machine == IMAGE_FILE_MACHINE_I386) && (pcode[0] == 0xff && pcode[1] == 0x15) &&
          ud_obj.operand->lval.udword >= _min_image_base && ud_obj.operand->lval.udword <= _max_image_base) {
          int gen_len = GenConfusionCallMem(ppa, ppa_rva, pcode, code_va_to_raw_offset, imagbase_offset);
          ppa += gen_len;
          add_code_length += gen_len;
        }
        else {
#ifdef _DEBUG
          __debugbreak();
#endif
        }
      }
      else if (dis_len == 5 && ud_obj.mnemonic == UD_Ipush && ud_obj.operand->type == UD_OP_IMM) {
        uint t1 = ud_obj.operand->lval.uqword;
        if (t1 >= _min_image_base && t1 <= _max_image_base) {
          int gen_len = GenConfusionPushImm(ppa, ppa_rva, pcode, dis_len, code_va_to_raw_offset, imagbase_offset, false);
          ppa += gen_len;
          add_code_length += gen_len;
        }
        else if (fileh->Machine == IMAGE_FILE_MACHINE_I386) {
          int gen_len = GenConfusionPushImm(ppa, ppa_rva, pcode, dis_len, code_va_to_raw_offset, imagbase_offset, true);
          ppa += gen_len;
          add_code_length += gen_len;
        }
      }
      pcode += dis_len;
    }
#if defined(_M_IX86)
    pcode = (unsigned char *)(imagebase + _section_raw);
    csh handle = { 0 };
    cs_err err = cs_open(CS_ARCH_X86, ((fileh->Machine == IMAGE_FILE_MACHINE_I386) ? CS_MODE_32 : CS_MODE_64), &handle);
    if (err == CS_ERR_OK) {
      cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
      uint64_t address = 0;
      cs_insn *insn;
      size_t count = cs_disasm(handle, pcode, _section_raw_sze, address, 0, &insn);
      for (uint instr_index = 0; instr_index < count; instr_index++) {
        int dis_len = insn[instr_index].size;
        if (dis_len >= 5 && (!strnicmp(insn[instr_index].mnemonic, "cmp", 3))) {
          int gen_len = GenConfusionCopyInstrJmpReturn(ppa, ppa_rva, pcode, dis_len, code_va_to_raw_offset, imagbase_offset);
          ppa += gen_len;
          add_code_length += gen_len;
        }
        pcode += dis_len;
      }
      cs_free(insn, count);
      insn = nullptr;
      cs_close(&handle);
    }
#endif
  }
#endif
  if (add_code_length) {
    psection[section_num - 1].SizeOfRawData = alignment(add_code_length, opth->FileAlignment);
    psection[section_num - 1].Misc.VirtualSize = alignment(add_code_length, opth->SectionAlignment);
    uint _new_image_offset = opth->SizeOfImage - psection[section_num - 1].VirtualAddress;
    opth->SizeOfImage -= _new_image_offset;
    opth->SizeOfImage += alignment(add_code_length, opth->SectionAlignment);
    Write<wchar_t>(path, (const char*)data_a.data(), add_code_length + data.size());
  }
  return add_code_length;
}