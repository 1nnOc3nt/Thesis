#include "ws2_32.h"

void Emuaccept(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD addr = 0;
	DWORD addrlen = 0;
	DWORD len = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get addr
	addr = getDWORD(uc, sp + 4);

	//Get addrlen
	addrlen = getDWORD(uc, sp + 8);
	len = getDWORD(uc, addrlen);

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, addr=0x%lX, addrlen=0x%lX)\n", s, addr, len);
	UcPrintAPIArg(buffer, tab);

	//Call accept
	DWORD retVal = (DWORD)accept((SOCKET)s, (sockaddr*)NULL, NULL);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 3;
}

void Emubind(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD name = 0;
	DWORD namelen = 0;
	SOCKADDR pSock;
	WORD port = 0;
	DWORD ip = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get name
	name = getDWORD(uc, sp + 4);
	err = uc_mem_read(uc, name, &pSock, sizeof(SOCKADDR));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_read(uc, name + 2, &port, sizeof(WORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	port = _byteswap_ushort(port);

	err = uc_mem_read(uc, name + 4, &ip, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	ip = _byteswap_ulong(ip);

	struct in_addr addr;
	addr.s_addr = htonl(ip);
	TCHAR* ipAddr = inet_ntoa(addr);

	//Get namelen
	namelen = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, addr=0x%lX(%s:%d), namelen=0x%lX)\n", s, name, ipAddr, port, namelen);
	UcPrintAPIArg(buffer, tab);

	//Call bind
	DWORD retVal = bind((SOCKET)s, &pSock, namelen);
	if (retVal == SOCKET_ERROR)
		retVal = 0;

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 3;
}

void Emuconnect(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD name = 0;
	DWORD namelen = 0;
	SOCKADDR pSock;
	WORD port = 0;
	DWORD ip = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get name
	name = getDWORD(uc, sp + 4);
	err = uc_mem_read(uc, name, &pSock, sizeof(SOCKADDR));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	err = uc_mem_read(uc, name + 2, &port, sizeof(WORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	port = _byteswap_ushort(port);

	err = uc_mem_read(uc, name + 4, &ip, sizeof(DWORD));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	ip = _byteswap_ulong(ip);

	struct in_addr addr;
	addr.s_addr = htonl(ip);
	TCHAR* ipAddr = inet_ntoa(addr);

	//Get namelen
	namelen = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, name=0x%lX(%s:%d), namelen=0x%lX)\n", s, name, ipAddr, port, namelen);
	UcPrintAPIArg(buffer, tab);

	//Call connect
	DWORD retVal = connect((SOCKET)s, &pSock, namelen);
	if (retVal == SOCKET_ERROR)
		retVal = 0;

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 3;
}

void Emuclosesocket(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(s=0x%lX)\n", s);
	UcPrintAPIArg(buffer, tab);

	//Call closesocket
	DWORD retVal = closesocket((SOCKET)s);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 1;
}

void Emugetsockopt(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD level = 0;
	DWORD optname = 0;
	DWORD optval = 0;
	DWORD optlen = 0;
	DWORD iOptVal = 0;
	int iOptLen = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get level
	level = getDWORD(uc, sp + 4);

	//Get optname
	optname = getDWORD(uc, sp + 8);

	//Get optval
	optval = getDWORD(uc, sp + 12);

	//Get optlen
	optlen = getDWORD(uc, sp + 16);
	iOptLen = getDWORD(uc, optlen);

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, level=0x%lX, optname=0x%lX, optval=0x%lX, optlen=&0x%lX)\n", s, level, optname, optval, iOptLen);
	UcPrintAPIArg(buffer, tab);

	//Call getsockopt
	DWORD retVal = getsockopt((SOCKET)s, level, optname, (char*) &iOptVal, &iOptLen);
	if (retVal == SOCKET_ERROR)
		retVal = 0;

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Write optval
	err = uc_mem_write(uc, optval, &iOptVal, sizeof(iOptVal));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 5;
}

void Emulisten(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD backlog = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get backlog
	backlog = getDWORD(uc, sp + 4);

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, backlog=0x%lX)\n", s, backlog);
	UcPrintAPIArg(buffer, tab);

	//Call listen
	DWORD retVal = listen(s, backlog);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 2;
}

void Emurecv(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD buf = 0;
	DWORD len = 0;
	DWORD flags;
	TCHAR* b = NULL;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get buf
	buf = getDWORD(uc, sp + 4);

	//Get len
	len = getDWORD(uc, sp + 8);

	//Get flags
	flags = getDWORD(uc, sp + 12);

	//Init buf
	b = new TCHAR[len];

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, buf=0x%lX, len=0x%lX, flags=0x%lX)\n", s, buf, len, flags);
	UcPrintAPIArg(buffer, tab);

	//Call recv
	DWORD retVal = recv((SOCKET)s, b, len, flags);
	if (retVal == SOCKET_ERROR)
		retVal = len;

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Write buf
	err = uc_mem_write(uc, buf, b, len);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 4;
	delete b;
}

void Emusend(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD buf = 0;
	DWORD len = 0;
	DWORD flags;
	TCHAR* b = NULL;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get buf
	buf = getDWORD(uc, sp + 4);

	//Get len
	len = getDWORD(uc, sp + 8);

	//Get flags
	flags = getDWORD(uc, sp + 12);

	//Read buf
	b = new TCHAR[len];
	err = uc_mem_read(uc, buf, b, len);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, buf=0x%lX, len=0x%lX, flags=0x%lX)\n", s, buf, len, flags);
	UcPrintAPIArg(buffer, tab);

	//Call send
	DWORD retVal = send((SOCKET)s, b, len, flags);
	if (retVal == SOCKET_ERROR)
		retVal = len;

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 4;
	delete b;
}

void Emusetsockopt(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD s = 0;
	DWORD level = 0;
	DWORD optname = 0;
	DWORD optval = 0;
	DWORD optlen = 0;
	DWORD bOptVal = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get s
	s = getDWORD(uc, sp);

	//Get level
	level = getDWORD(uc, sp + 4);

	//Get optname
	optname = getDWORD(uc, sp + 8);

	//Get optval
	optval = getDWORD(uc, sp + 12);
	bOptVal = getDWORD(uc, optlen);

	//Get optlen
	optlen = getDWORD(uc, sp + 16);

	//Print arguments
	_stprintf(buffer, "(s=0x%lX, level=0x%lX, optname=0x%lX, optval=&0x%lX, optlen=0x%lX)\n", s, level, optname, bOptVal, optlen);
	UcPrintAPIArg(buffer, tab);

	//Call setsockopt
	DWORD retVal = setsockopt((SOCKET)s, level, optname, (char*)& bOptVal, optlen);
	if (retVal == SOCKET_ERROR)
		retVal = 0;

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 5;
}

void Emusocket(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD af = 0;
	DWORD type = 0;
	DWORD protocol = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get af
	af = getDWORD(uc, sp);

	//Get type
	type = getDWORD(uc, sp + 4);

	//Get protocol
	protocol = getDWORD(uc, sp + 8);

	//Print arguments
	_stprintf(buffer, "(af=0x%lX, type=0x%lX, protocol=0x%lX)\n", af, type, protocol);
	UcPrintAPIArg(buffer, tab);

	//Call socket
	DWORD retVal = socket(af, type, protocol);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 3;
}

void EmuWSACleanup(uc_engine* uc, DWORD tab)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print argument
	strcat(buffer, "\n");
	UcPrintAPIArg(buffer, tab);

	//Call WSACleanup
	DWORD retVal = WSACleanup();

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void EmuWSAGetLastError(uc_engine* uc, DWORD tab)
{
	uc_err err;
	TCHAR buffer[MAX_PATH] = { 0 };

	//Print argument
	strcat(buffer, "\n");
	UcPrintAPIArg(buffer, tab);

	//Call WSAGetLastError
	DWORD retVal = WSAGetLastError();

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 0;
}

void EmuWSASetLastError(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD iError = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get iError
	iError = getDWORD(uc, sp);

	//Print argument
	_stprintf(buffer, "(iError=0x%lX)\n", iError);
	UcPrintAPIArg(buffer, tab);

	//Call WSASetLastError
	DWORD retVal = 0;
	WSASetLastError(iError);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 1;
}

void EmuWSASocket(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD af = 0;
	DWORD type = 0;
	DWORD protocol = 0;
	DWORD lpProtocolInfo = 0;
	DWORD g = 0;
	DWORD dwFlags = 0;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get af
	af = getDWORD(uc, sp);

	//Get type
	type = getDWORD(uc, sp + 4);

	//Get protocol
	protocol = getDWORD(uc, sp + 8);

	//Get lpProtocolInfo
	lpProtocolInfo = getDWORD(uc, sp + 12);

	//Get g
	g = getDWORD(uc, sp + 16);

	//Get dwFlags
	dwFlags = getDWORD(uc, sp + 20);

	//Print arguments
	_stprintf(buffer, "(af=0x%lX, type=0x%lX, protocol=0x%lX, lpProtocolInfo=0x%lX, g=0x%lX, dwFlags=0x%lX)\n", af, type, protocol, lpProtocolInfo, g, dwFlags);
	UcPrintAPIArg(buffer, tab);

	//Call WSASsocket
	DWORD retVal = WSASocket(af, type, protocol, NULL, 0, dwFlags);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 6;
}

void EmuWSAStartup(uc_engine* uc, DWORD tab)
{
	uc_err err;
	DWORD wVersionRequired = 0;
	DWORD lpWSAData = 0;
	WSADATA wsaData;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD sp = 0;

	//Get stack pointer
	err = uc_reg_read(uc, UC_X86_REG_ESP, &sp);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	sp += 4;

	//Get wVersionRequired
	wVersionRequired = getDWORD(uc, sp);

	//Get lpWSAData
	lpWSAData = getDWORD(uc, sp + 4);

	//Print arguments
	_stprintf(buffer, "(wVersionRequired=0x%lX, lpWSAData=0x%lX)\n", wVersionRequired, lpWSAData);
	UcPrintAPIArg(buffer, tab);

	//Call WSAStartup
	DWORD retVal = WSAStartup(wVersionRequired, &wsaData);

	//Set last error
	DWORD errorCode = GetLastError();
	UcSetLastError(uc, errorCode);

	//Write wsaData
	err = uc_mem_write(uc, lpWSAData, &wsaData, sizeof(WSADATA));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	//Push return value back to EAX
	err = uc_reg_write(uc, UC_X86_REG_EAX, &retVal);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);

	_numberOfArguments = 2;
}