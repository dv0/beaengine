// BE_Test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#define BEA_ENGINE_STATIC  /* specify the usage of a static version of BeaEngine */
//#define BEA_USE_STDCALL    /* specify the usage of a stdcall version of BeaEngine */
#include "BeaEngine.h"
#include "windows.h"

#pragma comment(lib,"beaengine.lib")

/* ============================= Init datas */
DISASM MyDisasm;
int len;

void *pBuffer;
int(*pSourceCode) (void);     /* function pointer */

/* ===============================================================================*/
/*
/*  Disassemble code in the specified buffer using the correct VA
/*
/* ===============================================================================*/

int DisassembleCode(char *StartCodeSection,char *EndCodeSection,void* Virtual_Address)
{
	int iCmdCount = 0;
	BOOL Error = 0;
	/* ============================= Init the Disasm structure (important !)*/
	//(void)memset(&MyDisasm, 0, sizeof(DISASM));

	/* ============================= Init EIP */
	MyDisasm.EIP = (UIntPtr)StartCodeSection;
	/* ============================= Init VirtualAddr */
	MyDisasm.VirtualAddr = (long long)Virtual_Address;

	/* ============================= set IA-32 architecture */
	MyDisasm.Archi = 32;

	/* ============================= Loop for Disasm */
	while (!Error)
	{
		/* ============================= Fix SecurityBlock */
		MyDisasm.SecurityBlock =(UInt32)( EndCodeSection - MyDisasm.EIP);

		len = Disasm(&MyDisasm);

		if (len > 0)
		{

			iCmdCount++;
			//(void)printf("%.8X %s\n", (int)MyDisasm.VirtualAddr, &MyDisasm.CompleteInstr);
			MyDisasm.EIP = MyDisasm.EIP + len;
			MyDisasm.VirtualAddr = MyDisasm.VirtualAddr + len;
			if (MyDisasm.EIP >= (int)EndCodeSection) 
			{
				//(void)printf("End of buffer reached ! \n");
				Error = 1;
			}
		}
		else
		{
			//printf("fuck!");
			break;
		}
	};
	return iCmdCount;
}

/* ===============================================================================*/
/*
/*                      MAIN
/*
/* ===============================================================================*/
int main(void)
{
	pSourceCode = &main;

	pBuffer = malloc(110);

	unsigned char data[110] = {
		0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x53, 0x56, 0x57, 0x8D, 0xBD, 0x40, 0xFF,
		0xFF, 0xFF, 0xB9, 0x30, 0x00, 0x00, 0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xF3, 0xAB, 0x8B, 0x45,
		0x08, 0x8B, 0x88, 0x20, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0x11, 0x8B, 0x45, 0x08, 0x89, 0x50, 0x2C,
		0x8B, 0xF4, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x4D, 0x08, 0x8B, 0x91, 0x20, 0x01, 0x00, 0x00, 0x0F,
		0xB6, 0x02, 0x8B, 0x0C, 0x85, 0x58, 0xD0, 0x40, 0x01, 0xFF, 0xD1, 0x83, 0xC4, 0x04, 0x3B, 0xF4,
		0xE8, 0xF3, 0x08, 0xFC, 0xFF, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5F, 0x5E, 0x5B, 0x81, 0xC4, 0xC0,
		0x00, 0x00, 0x00, 0x3B, 0xEC, 0xE8, 0xDE, 0x08, 0xFC, 0xFF, 0x8B, 0xE5, 0x5D, 0xC3
	};
	(void)memcpy(pBuffer, (void*)data, 110);
//   	01403090                         55                        push    ebp
// 		01403091                         8BEC                      mov     ebp, esp
// 		01403093                         81EC C0000000             sub     esp, 0C0
// 		01403099                         53                        push    ebx
// 		0140309A                         56                        push    esi
// 		0140309B                         57                        push    edi
// 		0140309C                         8DBD 40FFFFFF             lea     edi, dword ptr[ebp - C0]
// 		014030A2                         B9 30000000               mov     ecx, 30
// 		014030A7                         B8 CCCCCCCC               mov     eax, CCCCCCCC
// 		014030AC                         F3:AB                     rep     stos dword ptr es : [edi]
// 		014030AE                         8B45 08                   mov     eax, dword ptr[ebp + 8]
// 		014030B1                         8B88 20010000             mov     ecx, dword ptr[eax + 120]
// 		014030B7                         0FB611                    movzx   edx, byte ptr[ecx]
// 		014030BA                         8B45 08                   mov     eax, dword ptr[ebp + 8]
// 		014030BD                         8950 2C                   mov     dword ptr[eax + 2C], edx
// 		014030C0                         8BF4                      mov     esi, esp
// 		014030C2                         8B45 08                   mov     eax, dword ptr[ebp + 8]
// 		014030C5                         50                        push    eax
// 		014030C6                         8B4D 08                   mov     ecx, dword ptr[ebp + 8]
// 		014030C9                         8B91 20010000             mov     edx, dword ptr[ecx + 120]
// 		014030CF                         0FB602                    movzx   eax, byte ptr[edx]
// 		014030D2                         8B0C85 58D04001           mov     ecx, dword ptr[eax * 4 + opcode_map1]
// 		014030D9                         FFD1                      call    ecx
// 		014030DB                         83C4 04                   add     esp, 4
// 		014030DE                         3BF4                      cmp     esi, esp
// 		014030E0                         E8 F308FCFF               call    013C39D8
// 		014030E5                         B8 01000000               mov     eax, 1
// 		014030EA                         5F                        pop     edi
// 		014030EB                         5E                        pop     esi
// 		014030EC                         5B                        pop     ebx
// 		014030ED                         81C4 C0000000             add     esp, 0C0
// 		014030F3                         3BEC                      cmp     ebp, esp
// 		014030F5                         E8 DE08FCFF               call    013C39D8
// 		014030FA                         8BE5                      mov     esp, ebp
// 		014030FC                         5D                        pop     ebp
// 		014030FD                         C3                        retn



	DWORD t = GetTickCount();
	int i = 0;
	void* va = (void*)0x01403090;

	int iCmdCount = DisassembleCode((char*)pBuffer, (char*)pBuffer + 110, va);
	do 
	{
		i++;
		DisassembleCode((char*)pBuffer, (char*)pBuffer + 110, va);
	} while (i < 10000000);
	t = GetTickCount() - t;
	printf("%d CmdCount:%d %f %f %d\n", t, iCmdCount * i, (float)i / t, (float)i * iCmdCount / t * 1000, iCmdCount);
	getchar();

	return 0;
}