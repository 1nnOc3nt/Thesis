#include "GDT.h"

GDT* gdt;

GDT::GDT(uc_engine* uc, DWORD gdtAddr, DWORD gdtLimit, DWORD gdtNumber)
{
	uc_err err;
	uc_x86_mmr gdtr;

	//Map memory for GDT
	err = uc_mem_map(uc, GDT_ADDR, GDT_LIMIT, UC_PROT_ALL);

	//Setup GDTR
	gdtr.base = GDT_ADDR;
	gdtr.limit = GDT_LIMIT;
	gdtr.flags = 0;
	gdtr.selector = 0;

	err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);

	//Restore values
	this->gdtNumber = gdtNumber;
	this->gdtAddr = gdtAddr;
	this->gdtLimit = gdtLimit;
}

void GDT::RegisterGDTSegment(uc_engine* uc, DWORD index, DWORD segAddr, DWORD segSize, DWORD sPort, DWORD rPort)
{
	uc_err err;
	if (index == 10)
	{
		err = uc_mem_map(uc, segAddr, segSize, UC_PROT_ALL);
		if (err != UC_ERR_OK)
			HandleUcErrorVoid(err);
	}

	if (index < 0 || index >= this->gdtNumber)
	{
		_tprintf("[!] Error: GDT register index error!\n");
		return;
	}

	//Create GDT entry, then write gdt entry into GDT table
	UINT64 gdtEntry = CreateGDTEntry(segAddr, segSize, sPort, F_PROT_32);
	err = uc_mem_write(uc, this->gdtAddr + (index << 3), &gdtEntry, sizeof(UINT64));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

UINT64 GDT::CreateGDTEntry(DWORD base, DWORD limit, DWORD access, DWORD flags)
{
	UINT64 ret = (UINT64)limit & 0xffff;
	ret |= ((UINT64)base & 0xffffff) << 16;
	ret |= ((UINT64)access & 0xff) << 40;
	ret |=(((UINT64)limit >> 16) & 0xf) << 48;
	ret |= ((UINT64)flags & 0xff) << 52;
	ret |= (((UINT64)base >> 24) & 0xff) << 56;
	return ret;
}

DWORD GDT::CreateSelector(DWORD index, DWORD flags)
{
	DWORD ret = flags;
	ret |= index << 3;
	return ret;
}

TCHAR* GDT::getGDTBuf(uc_engine* uc, DWORD start, DWORD end) const
{
	uc_err err;
	TCHAR* outBuf = NULL;
	err = uc_mem_read(uc, this->gdtAddr + (start << 3), outBuf, (end << 3) - (start << 3));
	if (err != UC_ERR_OK)
		HandleUcErrorNull(err);
	return outBuf;
}

void GDT::setGDTBuf(uc_engine* uc, UINT32 start, UINT32 end, TCHAR* writeBuf)
{
	uc_err err;
	err = uc_mem_write(uc, this->gdtAddr + (start << 3), writeBuf, (end << 3) - (start << 3));
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

GDT::~GDT()
{

}

void Register_cs(uc_engine* uc, GDT* gdtm)
{
	uc_err err;
	gdtm->RegisterGDTSegment(uc, 4, 0, 0xfffff000, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, S_GDT | S_PRIV_3);
	DWORD value = gdtm->CreateSelector(4, S_GDT | S_PRIV_3);
	err = uc_reg_write(uc, UC_X86_REG_CS, &value);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Register_ds_ss_es(uc_engine* uc, GDT* gdtm)
{
	uc_err err;
	gdtm->RegisterGDTSegment(uc, 5, 0, 0xfffff000, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, S_GDT | S_PRIV_0);
	DWORD value = gdtm->CreateSelector(5, S_GDT | S_PRIV_0);
	err = uc_reg_write(uc, UC_X86_REG_DS, &value);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
	uc_reg_write(uc, UC_X86_REG_SS, &value);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
	uc_reg_write(uc, UC_X86_REG_ES, &value);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Register_fs(uc_engine* uc, GDT* gdtm)
{
	uc_err err;
	gdtm->RegisterGDTSegment(uc, 10, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, S_GDT | S_PRIV_3);
	DWORD value = gdtm->CreateSelector(10, S_GDT | S_PRIV_3);
	err =uc_reg_write(uc, UC_X86_REG_FS, &value);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}

void Register_gs(uc_engine* uc, GDT* gdtm)
{
	uc_err err;
	gdtm->RegisterGDTSegment(uc, 5, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, S_GDT | S_PRIV_3);
	DWORD value = gdtm->CreateSelector(5, S_GDT | S_PRIV_0);
	err = uc_reg_write(uc, UC_X86_REG_GS, &value);
	if (err != UC_ERR_OK)
		HandleUcErrorVoid(err);
}