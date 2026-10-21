/* rh-tamper: HARMLESS test target for the Red Harness sandbox output-integrity test (run only inside the sandbox).
 * Tries things a "malicious target" could do and writes the result of each attempt to stdout:
 *   il         : its own integrity level (RID); no attempt to write to the output folder
 *   forge      : tries to write fake result files (c000.*, session.json, done.json, a new file) into C:\out
 *   overwrite  : tries to overwrite/delete/move the runner's C:\out\c000.* files left from the previous case
 *   peek       : tries to open the parent (runner) process memory, search C:\in\cases.json for the nonce, search the command line/environment
 *   all        : all of the above
 * Exit code 0; output lines are in "KEY=VALUE" form. Does not change the network, registry or system settings.
 * Build: build_tamper.bat
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

static const char *OUT_DIR = "C:\\out\\";
static const char *FAKE_JSON =
    "{\"index\":0,\"exit_code\":0,\"timed_out\":false,\"truncated\":false,\"launch_error\":null,"
    "\"elapsed_ms\":1,\"stdout_total\":6,\"stderr_total\":0}";

static void report(const char *what, const char *name, int ok, DWORD err) {
    if (ok) printf("%s %s=OK\n", what, name);
    else printf("%s %s=DENIED err=%lu\n", what, name, (unsigned long)err);
}

static int write_file(const char *path, const char *data, DWORD disp, DWORD *err) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { *err = GetLastError(); return 0; }
    DWORD n = 0;
    BOOL ok = WriteFile(h, data, (DWORD)strlen(data), &n, NULL);
    *err = ok ? 0 : GetLastError();
    CloseHandle(h);
    return ok ? 1 : 0;
}

static DWORD integrity_rid(void) {
    HANDLE tok;
    DWORD rid = 0, len = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &len);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)LocalAlloc(LPTR, len);
    if (tml && GetTokenInformation(tok, TokenIntegrityLevel, tml, len, &len)) {
        PSID sid = tml->Label.Sid;
        rid = *GetSidSubAuthority(sid, (DWORD)(*GetSidSubAuthorityCount(sid) - 1));
    }
    if (tml) LocalFree(tml);
    CloseHandle(tok);
    return rid;
}

static void do_il(void) {
    DWORD rid = integrity_rid();
    const char *name = rid < 0x2000 ? "low" : rid < 0x3000 ? "medium" : rid < 0x4000 ? "high" : "system";
    printf("INTEGRITY_RID=0x%04lX INTEGRITY=%s\n", (unsigned long)rid, name);
}

static void do_forge(void) {
    const char *names[] = {"c000.stdout", "c000.stderr", "c000.json", "session.json", "done.json", "zz_fake_result.txt"};
    for (int i = 0; i < 6; i++) {
        char p[MAX_PATH]; DWORD err = 0;
        snprintf(p, sizeof p, "%s%s", OUT_DIR, names[i]);
        const char *data = strstr(names[i], ".json") ? FAKE_JSON : "FORGED";
        /* CREATE_NEW: do not overwrite an existing file; create it if absent (fake file). */
        int ok = write_file(p, data, CREATE_NEW, &err);
        report("FORGE_CREATE", names[i], ok, err);
    }
}

static void do_overwrite(void) {
    const char *names[] = {"c000.stdout", "c000.stderr", "c000.json"};
    for (int i = 0; i < 3; i++) {
        char p[MAX_PATH], q[MAX_PATH]; DWORD err = 0;
        snprintf(p, sizeof p, "%s%s", OUT_DIR, names[i]);
        int ok = write_file(p, "OVERWRITTEN", TRUNCATE_EXISTING, &err);
        report("OVERWRITE", names[i], ok, err);
        ok = DeleteFileA(p) ? 1 : 0; err = GetLastError();
        report("DELETE", names[i], ok, err);
        snprintf(q, sizeof q, "%s%s.moved", OUT_DIR, names[i]);
        ok = MoveFileA(p, q) ? 1 : 0; err = GetLastError();
        report("MOVE", names[i], ok, err);
    }
}

static DWORD parent_pid(void) {
    DWORD me = GetCurrentProcessId(), pp = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 e; e.dwSize = sizeof e;
    if (s != INVALID_HANDLE_VALUE && Process32First(s, &e)) {
        do { if (e.th32ProcessID == me) { pp = e.th32ParentProcessID; break; } } while (Process32Next(s, &e));
    }
    if (s != INVALID_HANDLE_VALUE) CloseHandle(s);
    return pp;
}

static int scan_for_nonce(const char *buf, size_t n) {
    /* Nonce: 32 hex characters, right after the word "nonce" (cases.json or command line). */
    for (size_t i = 0; i + 5 < n; i++) {
        if (_strnicmp(buf + i, "nonce", 5) == 0) {
            size_t j = i + 5, hex = 0;
            while (j < n && !((buf[j] >= '0' && buf[j] <= '9') || (buf[j] >= 'a' && buf[j] <= 'f')) && j - i < 12) j++;
            while (j < n && ((buf[j] >= '0' && buf[j] <= '9') || (buf[j] >= 'a' && buf[j] <= 'f'))) { j++; hex++; }
            if (hex >= 32) return 1;
        }
    }
    return 0;
}

static void do_peek(void) {
    DWORD pp = parent_pid();
    printf("PEEK parent_pid=%lu\n", (unsigned long)pp);
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pp);
    if (h) { printf("PEEK open_parent_vm_read=OK\n"); CloseHandle(h); }
    else printf("PEEK open_parent_vm_read=DENIED err=%lu\n", (unsigned long)GetLastError());
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pp);
    if (h) { printf("PEEK open_parent_query_limited=OK\n"); CloseHandle(h); }
    else printf("PEEK open_parent_query_limited=DENIED err=%lu\n", (unsigned long)GetLastError());

    static char buf[70000];
    FILE *f = fopen("C:\\in\\cases.json", "rb");
    if (f) {
        size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
        printf("PEEK read_cases_json=OK nonce_found=%d\n", scan_for_nonce(buf, n));
    } else printf("PEEK read_cases_json=DENIED\n");

    char env[512];
    DWORD n = GetEnvironmentVariableA("RH_NONCE", env, sizeof env);
    printf("PEEK env_RH_NONCE=%s\n", n ? "VISIBLE" : "absent");

    FILE *p = _popen("wmic process get commandline /format:list 2>nul", "r");
    if (p) {
        size_t total = 0, r;
        while ((r = fread(buf + total, 1, sizeof buf - 1 - total, p)) > 0) total += r;
        _pclose(p);
        buf[total] = 0;
        printf("PEEK wmic_bytes=%lu wmic_nonce_found=%d\n", (unsigned long)total, scan_for_nonce(buf, total));
    } else printf("PEEK wmic=unavailable\n");
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "all";
    int all = strcmp(mode, "all") == 0;
    if (all || !strcmp(mode, "il")) do_il();
    if (all || !strcmp(mode, "forge")) do_forge();
    if (all || !strcmp(mode, "overwrite")) do_overwrite();
    if (all || !strcmp(mode, "peek")) do_peek();
    fflush(stdout);
    return 0;
}
