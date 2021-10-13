/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "utils.h"

/* Any allocation over 128KB is directed directly to mmap, which we don't want. */
#define LESS_THAN_MMAP_THRESHOLD    (127 * 1024)
/* For a 64-bit executable, an arena has about 0x8000000 bytes of space before
 * it runs into another arena. 0x8000000 / 127KB is roughly 1032, so that's
 * our upper limit for the number of allocations we'll create. In practice,
 * you don't need nearly this many allocations to trigger the creation of a
 * new heap within a non-main arena. For 64-bit executables, a new heap
 * triggers at around ~500 allocations of 127KB each.
 */
#define NUM_ALLOCS                  1032
/* The expected distance is the chunk size plus room for the metadata. */
#define EXPECTED_CHUNK_DISTANCE     LESS_THAN_MMAP_THRESHOLD + 24

void *thread()
{
        void *pointers[NUM_ALLOCS];
        for (int i = 0; i < NUM_ALLOCS; i++) {
            pointers[i] = malloc(LESS_THAN_MMAP_THRESHOLD);
            int chunk_distance = (i > 0) ? pointers[i] - pointers[i-1] : EXPECTED_CHUNK_DISTANCE;
            /* If the chunk_distance is negative, a new heap was created
             * before the first heap. If greater than the expected distance,
             * then a new heap was created after the first heap.
             */
            if (chunk_distance < 0 ||
                chunk_distance > EXPECTED_CHUNK_DISTANCE) {
                DebugBreak();
            }
        }

        (void)pointers;
        return NULL;
}

int main(int argc, char** argv, char** envp)
{
        void* p1 = malloc(0x10);

        pthread_t thread1;
        pthread_create(&thread1, NULL, thread, NULL);
        pthread_join(thread1, NULL);

        (void)p1;
        return EXIT_SUCCESS;
}
