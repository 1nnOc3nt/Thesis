#pragma once
#include "Info.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sstream>

// CLONE FROM QILING 

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

// These msr registers are x86 specific
#define FSMSR  0xC0000100
#define GSMSR  0xC0000101

// WINDOWS SETUP VALUE
#define GS_SEGMENT_ADDR  0x6000
#define GS_SEGMENT_SIZE  0x6000

#define FS_SEGMENT_ADDR  0x6000
#define FS_SEGMENT_SIZE  0x6000

class GdtManager
{
private:
	int gdt_number;
	UINT32 gdt_addr;
	UINT32 gdt_limit;
public:
	GdtManager(uc_engine*, UINT32, UINT32, UINT32);
	~GdtManager();

	uc_err register_gdt_segment(uc_engine*, int, UINT32, UINT32, UINT32, UINT32);
	string _create_gdt_entry(UINT32, UINT32, UINT32, UINT32);
	uc_err get_gdt_buf(uc_engine*, UINT32, UINT32, void*);
	uc_err set_gdt_buf(uc_engine*, UINT32, UINT32, void*);
	int get_free_index(uc_engine*, UINT32, int);
	UINT32 _create_selector(int, UINT32);
	UINT32 create_selector(int, UINT32);
};

void register_cs(uc_engine*, GdtManager);
void register_ds_ss_es(uc_engine*, GdtManager);
void register_gs(uc_engine*, GdtManager);
void register_fs(uc_engine*, GdtManager);