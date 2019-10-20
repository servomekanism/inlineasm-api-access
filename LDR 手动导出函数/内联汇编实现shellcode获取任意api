#include "windows.h"

FARPROC LoadLibA(char *szModlePath,char* funcName)
{
	/*
	__IN szModlePath 要导入的dll地址
	__IN funcName 要查询这个dll里面的具体函数名
	__return 返回值是一个远call，保存的是这个funcName函数的地址
	*/
	__asm
	{
		mov eax,FS:[30h];
		mov eax,[eax+0Ch];
		mov eax,[eax+1Ch];//这个是第一个ldr_data结构指向第一个模块
		mov eax,[eax];//拿到第一个模块的门三地址  C:\Windows\system32\KERNELBASE.dll
		mov eax,[eax]//kernel32.dll
		mov ebx,[eax+08h];//GetDllBase = ebx
        //mov ebx,[eax+14h];//偏移为14h为这个dll的名称，有需要可以拿出来对比

		// 		现在进去dll内存操作
		mov eax,[ebx+3Ch];//获取PE头e_lfanew
		mov eax,[eax+ebx+78h];
		add eax,ebx;
		mov edi,[eax+1Ch];
		add edi,ebx;     //edx = AddressOfFunctions这张表的基值(已经指向第一个无名函数了)
		//查表，LoadLibraryW在kernel32中符号位为0x341    LoadLibraryA = 0x33e
		//mov esi,341H;
		mov esi,33EH; //LoadLibraryW
		sub esi,1h;//可以不用管
		mov eax,[edi+esi*4];
		add eax,ebx;//LoadLibraryW的地址
		push szModlePath
		call eax	//eax = 获取dll的起始地址
		

		mov esi,246h;//GetProcAddress
		sub esi,1;
		mov ecx,[edi+esi*4];
		add ecx,ebx;

		jmp L1
szFuncName: _EMIT 'A'
			_EMIT 'd'
			_EMIT 'd'
			_EMIT 0x00
			//硬编码字符串在代码段，如果不想让人看到你调用的函数，可以将名字计算hash
L1:
		//push offset szFuncName;
		push funcName;
		push eax;
		call ecx;//获取到funcName的地址，返回到eax中
	}  
	 //函数返回都是eax方式返回
}

int main()
{
	FARPROC Addr =LoadLibA("user32.dll","MessageBoxA");

	__asm
	{
		push 0;
		push 0;
		push 0;
		push 0;
		call eax;
	}
	return 0;
}