#include "common.h"
#include "peek_poke.h"
#include "hvcall.h"
#include "mm.h"

u64 mmap_lpar_addr;

int map_lv1() {
	int result = lv1_undocumented_function_114(0, 0xC, HV_SIZE, &mmap_lpar_addr);
	if (result != 0) {
		PRINTF("Error code %d calling lv1_undocumented_function_114\n", result);
		return 0;
	}
	
	result = mm_map_lpar_memory_region(mmap_lpar_addr, HV_BASE, HV_SIZE, 0xC, 0);
	if (result) {
		PRINTF("Error code %d calling mm_map_lpar_memory_region\n", result);
		return 0;
	}
	
	return 1;
}

void unmap_lv1() {
	if (mmap_lpar_addr != 0)
		lv1_undocumented_function_115(mmap_lpar_addr);
}

void dump_lv1() {
	if (mmap_lpar_addr == 0)
		return; // lv1 not mapped
	
	FILE *f = fopen(DUMP_FILENAME, "wb");
	u64 quad;
	for (u64 i = (u64)HV_BASE; i < HV_BASE + HV_SIZE; i += 8) {
		quad = lv2_peek(i);
		fwrite(&quad, 8, 1, f);
	}
	fclose(f);
}

void patch_lv2_protection() {
	// changes protected area of lv2 to first byte only
	lv1_poke(0x363a78, 0x0000000000000001ULL);
	lv1_poke(0x363a80, 0xe0d251b556c59f05ULL);
	lv1_poke(0x363a88, 0xc232fcad552c80d7ULL);
	lv1_poke(0x363a90, 0x65140cd200000000ULL);
}

int main(int argc, char *argv[]) {
	debug_wait_for_client();
	
	PRINTF("installing new poke syscall\n");
	install_new_poke();
	
	PRINTF("mapping lv1\n");
	if (!map_lv1()) {
		remove_new_poke();
		exit(0);
	}
	
	PRINTF("patching lv2 mem protection\n");
	patch_lv2_protection();
	
	/* PRINTF("unmapping lv1\n");
	unmap_lv1();
	
	PRINTF("installing syscall 36\n");
	install_syscall_36();
	
	PRINTF("installing vsh_open hook\n");
	install_vsh_open_hook();	
	
	PRINTF("installing misc lv2 patches\n");
	install_lv2_patches(); */
	
	PRINTF("removing new poke syscall\n");
	remove_new_poke();
	
	PRINTF("done, exiting\n");
	return 0;
}