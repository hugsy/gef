#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

int main(){
    void *small = malloc(0x10); // small chunk
    malloc(0x20); // avoid consolidation of chunks
    void *large = malloc(0x410); // large chunk
    malloc(0x20); // avoid consolidation of chunks
    free(small);
    free(large);
    void *unsorted = malloc(0x420); // make sure the unsorted chunk is bigger than large chunk
    malloc(0x420); // sort the freed chunks from unsorted to their corresponding bins
    free(unsorted);
    DebugBreak();
    return EXIT_SUCCESS;
}
