/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 *
 * heap-fastbins.c
 *
 * @author: @_hugsy_
 * @author: @_theguy147_
 * @licence: WTFPL v.2
 */

#include <stdio.h>
#include <stdlib.h>

void break_here() {
	// GDB: `br *break_here`
}

int main(int argc, char** argv, char** envp) {
	// allocate some chunks that have a suitable size for a fastbin
	void* ptrs[10];
	for (int i = 0; i < 10; i++) {
		ptrs[i] = malloc(0x10);
	}
	// free 7 chunks to fill the tcache
	for (int i = 0; i < 7; i++) {
		free(ptrs[i]);
	}
	// now free our fastbin
	free(ptrs[7]);

	break_here(); // break here to check the `fastbinY` structure
}
