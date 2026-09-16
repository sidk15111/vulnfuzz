#include <stdio.h>
#include <stdlib.h>
#include "../src/vulnlib.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len < 0) {
        fclose(f);
        return 1;
    }

    unsigned char *buf = malloc((size_t)len);
    if (!buf) {
        fclose(f);
        return 1;
    }

    size_t nread = fread(buf, 1, (size_t)len, f);
    fclose(f);

    process_input(buf, nread);

    free(buf);
    printf("done, no crash\n");
    return 0;
}
