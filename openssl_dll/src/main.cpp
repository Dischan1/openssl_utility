#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "Ws2_32.lib")

#include <iostream>
//#include <Windows.h>
#include <cassert>
#include <string>
#include <filesystem>
#include <unordered_map>
#include <vector>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PcapFileDevice.h"
#include "PayloadLayer.h"
#include <EthLayer.h>
#include <IPv6Layer.h>

#define PACKET_OUTPUT_NAME "1_new_packet.pcap"

template<typename T = void**>
auto find_import(void* module_base, const char* func_name, const char* dll_name = nullptr) -> T
{
	assert(func_name);

	constexpr auto EQUAL = 0;

	auto base = reinterpret_cast<char*>(module_base);

	auto dos  = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	auto nt   = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
	auto opt  = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&nt->OptionalHeader);
	auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; desc->Name; ++desc)
	{
		auto name = reinterpret_cast<char*>(base + desc->Name);
		if (dll_name && std::strcmp(name, dll_name) != EQUAL) continue;

		auto thunk = reinterpret_cast<ULONG_PTR*>(base + desc->OriginalFirstThunk);
		auto func = reinterpret_cast<ULONG_PTR*>(base + desc->FirstThunk);

		if (!thunk)
			thunk = func;

		for (; *thunk; ++thunk, ++func)
		{
			if (IMAGE_SNAP_BY_ORDINAL(*thunk)) continue;

			auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + (*thunk));
			if (std::strcmp(import_by_name->Name, func_name) != EQUAL) continue;

			return reinterpret_cast<T>(func);
		}
	}

	return nullptr;
}

auto get_module_path(void* pfuncion) -> std::wstring
{
	MEMORY_BASIC_INFORMATION mbi;
	assert(VirtualQuery(pfuncion, &mbi, sizeof(mbi)) == sizeof(mbi));

	wchar_t module_path[MAX_PATH];
	assert(GetModuleFileNameW((HMODULE)mbi.AllocationBase, module_path, _countof(module_path)));

	return module_path;
}

char* get_ip_str(struct sockaddr* sa, char* s, size_t maxlen)
{ // https://stackoverflow.com/questions/69709140/winsock2-how-to-get-the-ipv4-ipv6-address-of-a-connected-client-after-server-si
	switch (sa->sa_family)
	{
		case AF_INET: return inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), s, maxlen), s;
		case AF_INET6: return inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), s, maxlen), s;
		default: return strncpy(s, "Unknown AF", maxlen), nullptr;
	}

	return s;
}

namespace ssl
{
	using _master_key = std::pair<unsigned char*, size_t>;

	HMODULE hmodule;

	struct ssl_ctx_st;
	struct ssl_method_st;
	struct ssl_session_st;

	struct ssl_st
	{
		int type;
		ssl_ctx_st* ctx;
	};

	struct _host_info
	{
		std::string ip;
		u_short port;
		bool is_ipv6;
	};

	int __fastcall ssl_read_detour(ssl_st* b, char* buf, unsigned __int64 size, unsigned __int64* readbytes);
	int __fastcall ssl_write_detour(ssl_st* b, const char* buf, unsigned __int64 size, unsigned __int64* written);
	ssl_ctx_st* __fastcall ssl_ctx_new_detour(const ssl_method_st* meth);

	void ssl_ctx_keylog_cb_func(const ssl_st* ssl, const char* line);

	decltype(ssl_read_detour)*    ssl_read_original    = nullptr;
	decltype(ssl_write_detour)*   ssl_write_original   = nullptr;
	decltype(ssl_ctx_new_detour)* ssl_ctx_new_original = nullptr;

	decltype(ssl_read_detour)**    ssl_read    = nullptr;
	decltype(ssl_write_detour)**   ssl_write   = nullptr;
	decltype(ssl_ctx_new_detour)** ssl_ctx_new = nullptr;

	auto initialize()	-> void;
	auto uninitialize()	-> void;

	auto get_master_key(ssl_st* ssl)   -> _master_key;
	auto dump_master_key(ssl_st* ssl)  -> void;
	auto dump_server_info(ssl_st* ssl) -> void;

	auto get_local_host_info(ssl_st* ssl)  -> _host_info;
	auto get_remote_host_info(ssl_st* ssl) -> _host_info;

	auto dump_packet(ssl_st* ssl, const char* buf, size_t size, bool outcoming) -> void;

	template<typename TRet, typename ...Args>
	auto call(const char* name, Args... args) -> TRet;

	pcpp::RawPacketVector packets;
	pcpp::PcapFileWriterDevice writer(PACKET_OUTPUT_NAME);
}

template<typename TRet, typename ...Args>
auto ssl::call(const char* name, Args... args) -> TRet
{
	static auto cache = std::unordered_map<std::string, void*>();

	if (cache.count(name) >= 1ull)
		return reinterpret_cast<TRet(__fastcall*)(Args...)>(cache[name])(args...);

	assert(cache[name] = GetProcAddress(hmodule, name));
	return reinterpret_cast<TRet(__fastcall*)(Args...)>(cache[name])(args...);
}

auto ssl::ssl_ctx_keylog_cb_func(const ssl_st* ssl, const char* line) -> void
{
	printf("log: %s\n", line); // ?? not working
}

int __fastcall 
ssl::ssl_read_detour(ssl_st* ssl, char* buf, unsigned __int64 size, unsigned __int64* readbytes)
{
	dump_master_key(ssl);
	dump_server_info(ssl);

	auto ret = ssl_read_original(ssl, buf, size, readbytes);
	if (ret < 0) return ret;

	dump_packet(ssl, buf, size, false);

	return ret;
}

int __fastcall 
ssl::ssl_write_detour(ssl_st* ssl, const char* buf, unsigned __int64 size, unsigned __int64* written)
{
	dump_master_key(ssl);
	dump_server_info(ssl);

	auto ret = ssl_write_original(ssl, buf, size, written);
	if (ret < 0) return ret;

	dump_packet(ssl, buf, size, true);

	return ret;
}

ssl::ssl_ctx_st* __fastcall
ssl::ssl_ctx_new_detour(const ssl_method_st* meth)
{
	auto ctx = ssl_ctx_new_original(meth); // ?? not working
	call<void>("SSL_CTX_set_keylog_callback", ctx, &ssl_ctx_keylog_cb_func);

	return ctx;
}

auto ssl::initialize() -> void
{
	assert(ssl_read    = find_import<decltype(ssl_read_detour)**>(GetModuleHandle(NULL), "SSL_read"));
	assert(ssl_write   = find_import<decltype(ssl_write_detour)**>(GetModuleHandle(NULL), "SSL_write"));
	assert(ssl_ctx_new = find_import<decltype(ssl_ctx_new_detour)**>(GetModuleHandle(NULL), "SSL_CTX_new"));

	auto ssl_module_name = std::filesystem::path(get_module_path(*ssl_read)).filename();
	assert(hmodule = GetModuleHandleW(ssl_module_name.c_str()));

	assert(ssl_read_original    = *ssl_read);
	assert(ssl_write_original   = *ssl_write);
	assert(ssl_ctx_new_original = *ssl_ctx_new);

	void* pointer[] { ssl_read, ssl_write, ssl_ctx_new };
	DWORD protect[_countof(pointer)];

	for (auto i = 0u; i < _countof(pointer); ++i)
	{
		protect[i] = PAGE_EXECUTE_READWRITE;
		VirtualProtect(pointer[i], USN_PAGE_SIZE, protect[i], &protect[i]);
	}

	*ssl_read    = &ssl_read_detour;
	*ssl_write   = &ssl_write_detour;
	*ssl_ctx_new = &ssl_ctx_new_detour;

	for (auto i = 0u; i < _countof(pointer); ++i)
		VirtualProtect(pointer[i], USN_PAGE_SIZE, protect[i], &protect[i]);

	printf("SSL_read:    %p -> %p\n", ssl_read_original, *ssl_read);
	printf("SSL_write:   %p -> %p\n", ssl_write_original, *ssl_write);
	printf("ssl_ctx_new: %p -> %p\n", ssl_ctx_new_original, *ssl_ctx_new);
}

auto ssl::uninitialize() -> void
{
	*ssl_read    = ssl_read_original;
	*ssl_write   = ssl_write_original;
	*ssl_ctx_new = ssl_ctx_new_original;
}

auto ssl::get_master_key(ssl_st* ssl) -> _master_key
{
	auto session = ssl::call<ssl::ssl_session_st*>("SSL_get_session", ssl);
	if (!session) return std::make_pair(nullptr, 0ull);

	auto len = ssl::call<uint64_t>("SSL_SESSION_get_master_key", session, NULL, 0);
	if (!len) return std::make_pair(nullptr, 0ull);

	auto key = reinterpret_cast<unsigned char*>(std::malloc(len));
	ssl::call<uint64_t>("SSL_SESSION_get_master_key", session, key, len);

	return std::make_pair(key, len);
}

auto ssl::dump_master_key(ssl_st* ssl) -> void
{
	auto master_key = get_master_key(ssl);
	if (!master_key.second) return;

	printf("-------------------------------- master key\n");

	for (auto i = 0u; i < master_key.second; ++i)
		printf("%02x ", master_key.first[i]);

	printf("\n");

	free(master_key.first);
}

auto ssl::dump_server_info(ssl_st* ssl) -> void
{
	printf("-------------------------------- server info\n");

	auto local = get_local_host_info(ssl);
	printf("address local: %s:%i\n", local.ip.c_str(), local.port);

	auto remote = get_remote_host_info(ssl);
	printf("address remote: %s:%i\n", remote.ip.c_str(), remote.port);
}

auto ssl::dump_packet(ssl_st* ssl, const char* buf, size_t size, bool outcoming) -> void
{
	constexpr auto MAC_EMPTY = "00:00:00:00:00:00";

	auto src = outcoming ? get_local_host_info(ssl) : get_remote_host_info(ssl);
	auto dst = outcoming ? get_remote_host_info(ssl) : get_local_host_info(ssl);

	auto payload_size = size ? size : std::strlen(buf);
	auto newPacket = new pcpp::Packet(payload_size);

	auto newEthernetLayer = pcpp::EthLayer(pcpp::MacAddress(MAC_EMPTY), pcpp::MacAddress(MAC_EMPTY));
	newPacket->addLayer(&newEthernetLayer);

	auto newIPv4Layer = pcpp::IPv4Layer(pcpp::IPv4Address(src.ip), pcpp::IPv4Address(dst.ip));
	auto newIPv6Layer = pcpp::IPv6Layer(pcpp::IPv6Address(src.ip), pcpp::IPv6Address(dst.ip));

	if (src.is_ipv6 && dst.is_ipv6)
		newPacket->addLayer(&newIPv6Layer);
	else
		newPacket->addLayer(&newIPv4Layer);

	auto newUdpLayer = pcpp::TcpLayer(src.port, dst.port);
	newPacket->addLayer(&newUdpLayer);

	auto payload = pcpp::PayloadLayer((uint8_t*)buf, payload_size, true);
	newPacket->addLayer(&payload);

	newPacket->computeCalculateFields();

	packets.pushBack(newPacket->getRawPacket());

	writer.open();
	writer.writePackets(packets);
	writer.close();
}

auto ssl::get_local_host_info(ssl_st* ssl) -> _host_info
{
	char buffer[MAX_PATH];
	auto sk = call<int>("SSL_get_fd", ssl);

	if (call<int>("SSL_get_servername_type", ssl) == 0)
	{
		sockaddr_in6 sa;
		std::memset(&sa, 0, sizeof(sa));

		int sa_size = sizeof(sa);

		getsockname(sk, reinterpret_cast<sockaddr*>(&sa), &sa_size);
		get_ip_str((sockaddr*)&sa, buffer, _countof(buffer));

		auto info = _host_info();
		info.ip = buffer;
		info.port = sa.sin6_port;
		info.is_ipv6 = true;

		return info;
	}

	sockaddr_in sa;
	std::memset(&sa, 0, sizeof(sa));

	int sa_size = sizeof(sa);

	getpeername(sk, reinterpret_cast<sockaddr*>(&sa), &sa_size);
	get_ip_str((sockaddr*)&sa, buffer, _countof(buffer));

	auto info = _host_info();
	info.ip = buffer;
	info.port = sa.sin_port;
	info.is_ipv6 = false;

	return info;
}

auto ssl::get_remote_host_info(ssl_st* ssl) -> _host_info
{
	char buffer[MAX_PATH];
	auto sk = call<int>("SSL_get_fd", ssl);

	if (call<int>("SSL_get_servername_type", ssl) == 0)
	{
		sockaddr_in6 sa;
		std::memset(&sa, 0, sizeof(sa));

		int sa_size = sizeof(sa);

		getpeername(sk, reinterpret_cast<sockaddr*>(&sa), &sa_size);
		get_ip_str((sockaddr*)&sa, buffer, _countof(buffer));

		auto info = _host_info();
		info.ip = buffer;
		info.port = sa.sin6_port;
		info.is_ipv6 = true;

		return info;
	}

	sockaddr_in sa;
	std::memset(&sa, 0, sizeof(sa));

	int sa_size = sizeof(sa);

	getpeername(sk, reinterpret_cast<sockaddr*>(&sa), &sa_size);
	get_ip_str((sockaddr*)&sa, buffer, _countof(buffer));

	auto info = _host_info();
	info.ip = buffer;
	info.port = sa.sin_port;
	info.is_ipv6 = false;

	return info;
}

auto on_dll_attach() -> DWORD
{
	MessageBoxW(NULL, L"Attached!\n", L"", NULL);

	ssl::initialize();

	return TRUE;
}

auto on_dll_detach() -> DWORD
{
	return TRUE;
}

DWORD WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			return on_dll_attach();
		case DLL_PROCESS_DETACH:
			return on_dll_detach();
	}

	return TRUE;
}