#pragma once
#include "Utils.h"

#define F_GRANULARITY  0x8
#define F_PROT_32  0x4
#define F_LONG  0x2
#define F_AVAILABLE  0x1

#define A_PRESENT  0x80

#define A_PRIV_3  0x60
#define A_PRIV_2  0x40
#define A_PRIV_1  0x20
#define A_PRIV_0  0x0

#define A_CODE  0x10
#define A_DATA  0x10
#define A_TSS  0x0
#define A_GATE  0x0
#define A_EXEC  0x8

#define A_DATA_WRITABLE  0x2
#define A_CODE_READABLE  0x2
#define A_DIR_CON_BIT  0x4

#define S_GDT  0x0
#define S_LDT  0x4
#define S_PRIV_3  0x3
#define S_PRIV_2  0x2
#define S_PRIV_1  0x1
#define S_PRIV_0  0x0

#define GDT_ADDR  0x3000
#define GDT_LIMIT  0x1000
#define GDT_ENTRY_SIZE  0x8

#define GDT_ADDR_PADDING  0xe0000000

#define FSMSR  0xC0000100
#define GSMSR  0xC0000101

#define GS_SEGMENT_ADDR  0x6000
#define GS_SEGMENT_SIZE  0x300000

#define FS_SEGMENT_ADDR  0x6000
#define FS_SEGMENT_SIZE  0x300000

class GDT
{
	private:
		DWORD gdtNumber;
		DWORD gdtAddr;
		DWORD gdtLimit;
	public:
		GDT(uc_engine* uc, DWORD gdtAddr = GDT_ADDR, DWORD gdtLimit = GDT_LIMIT, DWORD gdtNumber = 16);
		void RegisterGDTSegment(uc_engine* uc, DWORD index, DWORD segAddr, DWORD segSize, DWORD sPort, DWORD rPort);
		UINT64 CreateGDTEntry(DWORD base, DWORD limit, DWORD access, DWORD flags);
		DWORD CreateSelector(DWORD index, DWORD flags);
		TCHAR* getGDTBuf(uc_engine* uc, DWORD start, DWORD end) const;
		void setGDTBuf(uc_engine* uc, UINT32 start, UINT32 end, TCHAR* writeBuf);
		~GDT();
};

extern GDT* gdt;

void Register_cs(uc_engine* uc, GDT* gdtm);
void Register_ds_ss_es(uc_engine* uc, GDT* gdtm);
void Register_fs(uc_engine* uc, GDT* gdtm);
void Register_gs(uc_engine* uc, GDT* gdtm);