#include <stdio.h>
#include <stdlib.h>
namespace gossip {
void *malloc_s(size_t size) {
	if (!size)
		return NULL;

	void *new_mem = malloc(size);

	if (!new_mem) {
		fprintf(stderr, "fatal: memory exhausted (malloc of %zu bytes)\n", size);
		exit(-1);
	}

	return new_mem;
}
}
