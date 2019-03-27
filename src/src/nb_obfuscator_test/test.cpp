#include "pch.h"
#include <iostream>
#include <string>
#include "nb_obfuscator/nb_obfuscator.h"
#include <windows.h>

#ifdef _DEBUG
TEST(TestCaseName, TestName) {
#if defined(_M_IX86)
  EXPECT_TRUE(GenConfusion(L"E:\\workspace\\nb_obfuscator\\bin\\Win32\\Release\\nb_obfuscator_test.exe"));
#elif (defined(_M_X64) || defined(__IA64__))
  EXPECT_TRUE(GenConfusion(L"E:\\workspace\\nb_obfuscator\\bin\\x64\\Release\\nb_obfuscator_test.exe"));
#endif
}

#endif // _DEBUG

DWORD Align(DWORD dwNum, DWORD dwAlign)
{
  if (dwNum % dwAlign == 0)
  {
    return dwNum;
  }
  else
  {
    return (dwNum / dwAlign + 1) * dwAlign;
  }
}

int add_sec(const wchar_t* pe_file)
{
  char szFilePath[MAX_PATH];//要分析的文件名及路径
  OPENFILENAME ofn;//定义结构，调用打开对话框选择要分析的文件及其保存路径

  HANDLE hFile;// 文件句柄
  HANDLE hMapping;// 映射文件句柄
  LPVOID ImageBase;// 映射基址

  PIMAGE_DOS_HEADER  pDH = NULL;//指向IMAGE_DOS结构的指针
  PIMAGE_NT_HEADERS  pNtH = NULL;//指向IMAGE_NT结构的指针
  PIMAGE_FILE_HEADER pFH = NULL;;//指向IMAGE_FILE结构的指针
  PIMAGE_OPTIONAL_HEADER pOH = NULL;//指向IMAGE_OPTIONALE结构的指针
  PIMAGE_SECTION_HEADER pSH1 = NULL;//指向IMAGE_SECTION_TABLE结构的指针first
  PIMAGE_SECTION_HEADER pSH2 = NULL;//指向IMAGE_SECTION_TABLE结构的指针two
  PIMAGE_SECTION_HEADER pSH3 = NULL;//指向IMAGE_SECTION_TABLE结构的指针three

  //必要的初始换
  //选择要分析的文件后，经过3步打开并映射选择的文件到虚拟内存中
  //1.创建文件内核对象，其句柄保存于hFile，将文件在物理存储器的位置通告给操作系统
  hFile = CreateFile(pe_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (!hFile)
  {
    MessageBoxA(NULL, "打开文件错误", NULL, MB_OK);
    return 0;
  }

  //2.创建文件映射内核对象（分配虚拟内存），句柄保存于hFileMapping
  hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
  if (!hMapping)
  {
    CloseHandle(hFile);
    return FALSE;
  }

  //3.将文件数据映射到进程的地址空间，返回的映射基址保存在ImageBase中
  ImageBase = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
  if (!ImageBase)
  {
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return FALSE;
  }

  //IMAGE_DOS Header结构指针
  pDH = (PIMAGE_DOS_HEADER)ImageBase;
  //IMAGE_NT Header结构指针
  pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
  //IMAGE_File Header结构指针
  pFH = &pNtH->FileHeader;
  //IMAGE_Optional Header结构指针
  pOH = &pNtH->OptionalHeader;

  //IMAGE_SECTION_TABLE结构的指针3中方法
  pSH1 = IMAGE_FIRST_SECTION(pNtH);// IMAGE_FIRST_SECTION宏
  pSH2 = (PIMAGE_SECTION_HEADER)((DWORD)pNtH + sizeof(IMAGE_NT_HEADERS));
  pSH3 = (PIMAGE_SECTION_HEADER)((DWORD)pDH + pOH->SizeOfHeaders);

  // 检查文件是否是一个有效的PE文件
  // IMAGE_DOS_SIGNATURE 该值为4D5A
  // IMAGE_NT_SIGNATURE 该值为PE00
  if (pDH->e_magic != IMAGE_DOS_SIGNATURE || pNtH->Signature != IMAGE_NT_SIGNATURE)
  {
    printf("Not valid PE file...");
    return -1;
  }

  // 创建PSection指针指向原程序中的第一个Section，并创建一个新的Section结构体secToAdd
  PIMAGE_SECTION_HEADER pSection = NULL;
  IMAGE_SECTION_HEADER secToAdd = { 0 };
  pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pOH + pFH->SizeOfOptionalHeader);


  DWORD dwSectionNum = pFH->NumberOfSections;
  DWORD dwSectionAlign = pOH->SectionAlignment;
  DWORD dwFileAlign = pOH->FileAlignment;
  DWORD dwOEP = pOH->AddressOfEntryPoint;    // 程序执行入口地址
  dwOEP = (DWORD)(pOH->ImageBase + dwOEP);   // 映射起始地址+执行入口地址

  // 将PSection指向原程序中最后一个Section，根据最后一个Section的内容设置新的Section
  pSection = pSection + dwSectionNum - 1;

  // 设置新添加的section的名字
  strcpy((char *)secToAdd.Name, ".For");
  // 设置新添加的section的属性值，与最后一个section取值相同
  secToAdd.Characteristics = pSection->Characteristics;

  // 新section大小设置
  DWORD vsize = 0x234;
  secToAdd.Misc.VirtualSize = vsize;
  // 根据之前定义的Align函数调用，得到经过处理后的section尺寸大小，经调整后实际大小为0x234，对齐后大小为0x400
  secToAdd.SizeOfRawData = Align(secToAdd.Misc.VirtualSize, dwFileAlign);

  // 调用Align函数，得到经过内存对齐处理后的尺寸
  // 新Section的RVA等于原程序最后一个Section的RVA加上该节在内存中的映射尺寸
  secToAdd.VirtualAddress = pSection->VirtualAddress +
    Align(pSection->Misc.VirtualSize, dwSectionAlign);

  // 新Section的FA地址等于最后一个Section的FA加上该节的文件对齐尺寸
  secToAdd.PointerToRawData = pSection->PointerToRawData + pSection->SizeOfRawData;

  // pSection指向原程序中最后一个节表的下一个，写入新的节表结构
  pSection++;
  //pSection->Characteristics = 0xE00000E0;
  secToAdd.Characteristics = 0xE00000E0;
  memcpy(pSection, &secToAdd, sizeof(IMAGE_SECTION_HEADER));

  // 输出新添加的section的信息
  char cName[9];
  char cBuff[9];
  printf("\n节表添加成功，新节表的信息为：\n");
  printf("\nName = %s", secToAdd.Name);
  //memset(cName, 0, sizeof(cName));
  //memcpy(cName, secToAdd.Name, 4);
  //puts(cName);

  printf("\nVirtualSize = %08lX", secToAdd.Misc.VirtualSize);
  //wsprintf(cBuff, "%08lX", secToAdd.Misc.VirtualSize);
  //puts(cBuff);

  printf("\nVirtualAddress = %08lX", secToAdd.VirtualAddress);
  /*wsprintf(cBuff, "%08lX", secToAdd.VirtualAddress);
  puts(cBuff);*/

  printf("\nSizeOfRawData = %08lX", secToAdd.SizeOfRawData);
  //wsprintf(cBuff, "%08lX", secToAdd.SizeOfRawData);
  //puts(cBuff);

  printf("\nPointerToRawData = %08lX", secToAdd.PointerToRawData);
  //wsprintf(cBuff, "%08lX", secToAdd.PointerToRawData);
  //puts(cBuff);
  printf("\n");

  // 更改PE文件中节表的数量
  WORD dwSizeAdd = 0x1;
  pNtH->FileHeader.NumberOfSections += dwSizeAdd;
  //pFH->NumberOfSections += 1;

 // 修改程序的映像大小
  pOH->SizeOfImage = pOH->SizeOfImage + Align(secToAdd.Misc.VirtualSize, dwSectionAlign);

  // 修改文件大小
  BYTE bNum = '\x0';
  DWORD dwWritten = 0;
  ::SetFilePointer(hFile, 0, 0, FILE_END);
  ::WriteFile(hFile, &bNum, secToAdd.SizeOfRawData, &dwWritten, NULL);
  ::UnmapViewOfFile(ImageBase);
  ::CloseHandle(hMapping);
  ::CloseHandle(hFile);

  return 0;
}

TEST(TestCaseName1, TestName1) {
  std::wstring file;
  std::wcout << L"please input pe path:" << std::endl;
  std::wcin >> file;
  EXPECT_TRUE(GenConfusion(file.c_str()));
}