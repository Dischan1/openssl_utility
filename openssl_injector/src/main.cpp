#include <iostream>
#include <Windows.h>
#include <thread>
#include <chrono>

#define TARGET_PATH_APP L"C:\\SSL_binaries\\DLL\\x64\\Release\\bin\\openssl.exe"
#define TARGET_PATH_DLL L"G:\\repos\\openssl_utilites\\x64\\Debug\\openssl_dll.dll"

auto continue_process(const PROCESS_INFORMATION& pi) -> void
{
	ResumeThread(pi.hThread);
}

auto cleanup_process(const PROCESS_INFORMATION& pi) -> void
{
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

auto kill_process(const PROCESS_INFORMATION& pi) -> void
{
	TerminateProcess(pi.hThread, 0);
	continue_process(pi);
	cleanup_process(pi);
}

int main()
{
	auto si = STARTUPINFOW();
	auto pi = PROCESS_INFORMATION();

	const wchar_t* command_line = L"s_client --connect mail.ru:443";

	if (!CreateProcessW(TARGET_PATH_APP, const_cast<wchar_t*>(command_line), nullptr,
		nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
	{
		printf("startup error\n");
		return 1;
	}

	auto target_path_dll_len  = std::wcslen(TARGET_PATH_DLL) + 1u;
	auto target_path_dll_size = target_path_dll_len * sizeof(TARGET_PATH_DLL[0]);

	auto premote_path_dll = VirtualAllocEx(pi.hProcess, nullptr,
		target_path_dll_len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!premote_path_dll)
		return kill_process(pi), 2;

	if (!WriteProcessMemory(pi.hProcess, premote_path_dll, TARGET_PATH_DLL, target_path_dll_size, nullptr))
		return kill_process(pi), 3;

	auto pload_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryW);
	auto hthread = CreateRemoteThread(pi.hProcess, nullptr, 0ull, pload_library, premote_path_dll, NULL, nullptr);

	if (!hthread || hthread == INVALID_HANDLE_VALUE)
		return kill_process(pi), 4;

	CloseHandle(hthread);

	std::this_thread::sleep_for(std::chrono::seconds(1));

lexit:
	continue_process(pi);
	cleanup_process(pi);

	return 0;
}