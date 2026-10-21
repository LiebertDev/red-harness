/* rh-bytedump: Red Harness byte-fidelity test target. Reads stdin and argv as BYTES, writes a hex dump to stdout.
   Output contains only [0-9a-f] and line endings (stdout in binary mode; no conversion).
     CMDLINE <hex>        GetCommandLineA raw bytes (including the program name)
     ARGC <n>
     ARG <i> <hex>        argv[i] as parsed by the CRT (i>=1)
     STDIN <len> <hex>    all of stdin, raw bytes
   Harmless: no file/network/system changes. */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>

static void hex(const unsigned char *p, size_t n) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { putchar(d[p[i] >> 4]); putchar(d[p[i] & 15]); }
}

int main(int argc, char **argv) {
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    const char *cl = GetCommandLineA();
    fputs("CMDLINE ", stdout); hex((const unsigned char *)cl, strlen(cl)); fputs("\n", stdout);
    printf("ARGC %d\n", argc);
    for (int i = 1; i < argc; i++) { printf("ARG %d ", i); hex((const unsigned char *)argv[i], strlen(argv[i])); fputs("\n", stdout); }
    static unsigned char buf[1 << 20];
    size_t n = 0, r;
    while (n < sizeof buf && (r = fread(buf + n, 1, sizeof buf - n, stdin)) > 0) n += r;
    printf("STDIN %u ", (unsigned)n); hex(buf, n); fputs("\n", stdout);
    return 0;
}
