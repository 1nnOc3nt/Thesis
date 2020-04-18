#include "Arch.h"

GdtManager::GdtManager(uc_engine* uc, UINT32 gdt_addr = GDT_ADDR, UINT32 gdt_limit = GDT_LIMIT, UINT32 gdt_entry_entries = 16)
{
	uc_err err;
	uc_x86_mmr gdtr;

	// mapping memory for GDT
	err = uc_mem_map(uc, GDT_ADDR, GDT_LIMIT, UC_PROT_ALL);
	if (err != UC_ERR_OK)
	{
		//HandleUcError(err);
		printf("Error on mapping memory for GDT. Error value: %d\n", err);
		return;
	}
	
    // setup GDTR
    gdtr.base = GDT_ADDR;
    gdtr.limit = GDT_LIMIT;
    gdtr.flags = 0;
    gdtr.selector = 0;

    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);

    // restore values
    this->gdt_number = gdt_entry_entries;
    this->gdt_addr = gdt_addr;
    this->gdt_limit = gdt_limit;
}

GdtManager::~GdtManager()
{
}

uc_err GdtManager::register_gdt_segment(uc_engine* uc, int index, UINT32 seg_addr, UINT32 seg_size, UINT32 sport, UINT32 rport)
{
	uc_err err;
	if (index >= 14 && index <= 15)
		err = uc_mem_map(uc, seg_addr, seg_addr, UC_PROT_ALL);

	if (index < 0 || index >= this->gdt_number) {
		// print error
		return;
	}

	// create GDT entry, then write gdt entry into gdt table
	string gdt_entry = _create_gdt_entry(seg_addr, seg_size, sport, F_PROT_32);
	err = uc_mem_write(uc, this->gdt_addr + (index) << 3, gdt_entry.c_str(), 8);

	return err;
}

string GdtManager::_create_gdt_entry(UINT32 base, UINT32 limit, UINT32 access, UINT32 flags)
{
	UINT64 to_ret = limit & 0xffff;
	to_ret |= (base & 0xffffff) << 16;
	to_ret |= (access & 0xff) << 40;
	to_ret |= ((limit >> 16) & 0xf) << 48;
	to_ret |= (flags & 0xff) << 52;
	to_ret |= ((base >> 24) & 0xff) << 56;

	stringstream ss;
	ss << to_ret;

	return ss.str();
}

uc_err GdtManager::get_gdt_buf(uc_engine* uc, UINT32 start, UINT32 end, void* out_buf)
{
	return uc_mem_read(uc, this->gdt_addr + (start << 3), out_buf, (end << 3) - (start << 3));
}

uc_err GdtManager::set_gdt_buf(uc_engine* uc, UINT32 start, UINT32 end, void* write_buf)
{
	return uc_mem_write(uc, this->gdt_addr + (start << 3), write_buf, (end << 3) - (start << 3));
}

int GdtManager::get_free_index(uc_engine* uc, UINT32 start = 0, int end = -1)
{
	int index = -1;
	stringstream ss;
	UINT64 value;

	if (end == -1)
		end = this->gdt_number;

	for (int i = start; i < end; i++) {
		void* buf;
		uc_mem_read(uc, this->gdt_addr + (i << 3), buf, 8);
		ss << buf;
		ss >> hex >> value;
		if (value == 0) {
			index = i;
			break;
		}
	}

	return index;
}

UINT32 GdtManager::_create_selector(int index, UINT32 flags)
{
	UINT32 to_ret = flags;
	to_ret |= index << 3;

	return to_ret;
}

UINT32 GdtManager::create_selector(int idx, UINT32 flags)
{
	return _create_selector(idx, flags);
}

void register_cs(uc_engine* uc, GdtManager gdtm)
{
	gdtm.register_gdt_segment(uc, 3, 0, 0xfffff000, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, S_GDT | S_PRIV_3);
	uc_reg_write(uc, UC_X86_REG_CS, (VOID*)gdtm.create_selector(3, S_GDT | S_PRIV_3));
}

void register_ds_ss_es(uc_engine* uc, GdtManager gdtm)
{
	gdtm.register_gdt_segment(uc, 5, 0, 0xfffff000, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, S_GDT | S_PRIV_0);
	uc_reg_write(uc, UC_X86_REG_DS, (VOID*)gdtm.create_selector(5, S_GDT | S_PRIV_0));
	uc_reg_write(uc, UC_X86_REG_SS, (VOID*)gdtm.create_selector(5, S_GDT | S_PRIV_0));
	uc_reg_write(uc, UC_X86_REG_ES, (VOID*)gdtm.create_selector(5, S_GDT | S_PRIV_0));
}

void register_gs(uc_engine* uc, GdtManager gdtm)
{
	gdtm.register_gdt_segment(uc, 15, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, S_GDT | S_PRIV_3);
	uc_reg_write(uc, UC_X86_REG_GS, (VOID*)gdtm.create_selector(15, S_GDT | S_PRIV_0));
}

void register_fs(uc_engine* uc, GdtManager gdtm)
{
	gdtm.register_gdt_segment(uc, 14, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, S_GDT | S_PRIV_3);
	uc_reg_write(uc, UC_X86_REG_FS, (VOID*)gdtm.create_selector(14, S_GDT | S_PRIV_3));
}

