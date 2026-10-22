/* EH ground-truth fixtures for the dataflow slicer (analysis/dataflow/seh.py).
 *
 * Benign console program: no file/registry/network writes, no external
 * dependencies.  Every fixture function is noinline and exported so a slicer
 * can find it by name.  Each function:
 *   - sets a local `v` to 0,
 *   - calls a noinline helper that may raise/throw,
 *   - writes a known constant to `v` in the handler,
 *   - joins both paths,
 *   - compares the joined `v` with a volatile expected value (a volatile
 *     local keeps a real compare instruction on x86 instead of the dec/neg/
 *     sbb/inc equality idiom) and returns the comparison result
 *     (1 = expected handler value, 0 = the other path).
 *
 * main() runs every case once with the arguments recorded in
 * ground-truth.json and exits 0 only when all returned values match.
 *
 * Build flags and the exact compiler version are in build.ps1/ground-truth.json.
 * /MD is intentional: the x64 __try/__except handler must be the imported
 * __C_specific_handler so the PE scope table is resolvable by seh.py.
 */

#include <windows.h>

#define EH_NOINLINE __declspec(noinline)
#define EH_API extern "C" __declspec(dllexport) EH_NOINLINE
/* C++ linkage on purpose: with /EHsc an `extern "C"` function is assumed not
 * to throw (/EHc), which would let the compiler drop the catch edge. */
#define EH_CPP_API __declspec(dllexport) EH_NOINLINE

/* ------------------------------------------------------------------ helpers */

/* Throws a C++ exception when mode != 0.  Kept out of line so the caller
 * cannot prove the throw away. */
EH_CPP_API void eh_throw_cpp(int mode)
{
    if (mode != 0)
        throw 1;
}

/* Raises a software exception when mode != 0. */
EH_API void eh_raise_seh(int mode)
{
    if (mode != 0)
        RaiseException(0xE0000001u, 0, 0, NULL);
}

/* Filter used by every __except case.  Returns EXCEPTION_EXECUTE_HANDLER (1)
 * for the fixture's exception code, EXCEPTION_CONTINUE_SEARCH otherwise. */
EH_API int eh_seh_filter(EXCEPTION_POINTERS *info)
{
    if (info != NULL && info->ExceptionRecord != NULL &&
        info->ExceptionRecord->ExceptionCode == 0xE0000001u)
        return EXCEPTION_EXECUTE_HANDLER;
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Writes 1 through a pointer: the no-EH control's callee. */
EH_API void eh_set_one(volatile int *p)
{
    *p = 1;
}

/* ------------------------------------------------------- x64 + x86 fixtures */

/* C++ try/catch.  Paths at the join:
 *   call returns  -> v == 0
 *   catch (...)   -> v == 1
 * Runtime mode = 1 (throw): joined v == 1, compare true, returns 1. */
EH_API int eh_cpp_try_catch(int mode)
{
    volatile int v = 0;
    try {
        eh_throw_cpp(mode);
    } catch (...) {
        v = 1;
    }
    volatile int expected = 1;
    return v == expected;
}

/* SEH __try/__except with an out-of-line filter.  Paths at the join:
 *   no exception  -> v == 0
 *   handler block -> v == 1
 * Runtime mode = 1 (RaiseException): joined v == 1, compare true, returns 1. */
EH_API int eh_seh_try_except(int mode)
{
    volatile int v = 0;
    __try {
        eh_raise_seh(mode);
    } __except (eh_seh_filter(GetExceptionInformation())) {
        v = 1;
    }
    volatile int expected = 1;
    return v == expected;
}

/* No-EH control.  The callee writes 1; there is exactly one path and no
 * handler.  Runtime mode = 0: joined v == 1, compare true, returns 1. */
EH_API int eh_no_eh_control(int mode)
{
    volatile int v = 0;
    (void)mode;
    eh_set_one(&v);
    volatile int expected = 1;
    return v == expected;
}

/* ------------------------------------------------------------- x64 fixtures */

#if defined(_M_X64)

/* SEH __try/__finally.  Paths:
 *   normal completion -> __finally writes v = 1, then compare true -> returns 1
 *   raised exception  -> __finally still writes v = 1, but with no enclosing
 *                        handler the function does not reach the compare
 * Runtime mode = 0: joined v == 1, compare true, returns 1. */
EH_API int eh_seh_try_finally(int mode)
{
    volatile int v = 0;
    __try {
        eh_raise_seh(mode);
    } __finally {
        v = 1;
    }
    volatile int expected = 1;
    return v == expected;
}

/* Nested handlers.  Inner __try raises; the inner filter accepts, writes
 * v = 2, then the normal continuation does v = v + 1.  Paths at the join:
 *   no exception, inner normal -> v == 1 (compare false)
 *   inner handler taken        -> v == 3 (compare true)
 *   outer handler taken        -> v == 4 (compare false)
 * Runtime mode = 1: the inner handler handles the exception, joined v == 3,
 * compare true, returns 1. */
EH_API int eh_nested_handler(int mode)
{
    volatile int v = 0;
    __try {
        __try {
            eh_raise_seh(mode);
        } __except (eh_seh_filter(GetExceptionInformation())) {
            v = 2;
        }
        v = v + 1;
    } __except (eh_seh_filter(GetExceptionInformation())) {
        v = 4;
    }
    volatile int expected = 3;
    return v == expected;
}

#endif /* _M_X64 */

/* ------------------------------------------------------------------- driver */

static int eh_failures;

static EH_NOINLINE void eh_check(const char *name, int got, int want)
{
    if (got != want) {
        /* Deterministic, no-formatting diagnostic to stderr. */
        DWORD written = 0;
        DWORD n = 0;
        while (name[n] != '\0')
            n++;
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), name, n, &written, NULL);
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), ": mismatch\r\n", 12, &written, NULL);
        eh_failures++;
    }
}

EH_NOINLINE int main(void)
{
    eh_check("eh_cpp_try_catch", eh_cpp_try_catch(1), 1);
    eh_check("eh_seh_try_except", eh_seh_try_except(1), 1);
#if defined(_M_X64)
    eh_check("eh_seh_try_finally", eh_seh_try_finally(0), 1);
    eh_check("eh_nested_handler", eh_nested_handler(1), 1);
#endif
    eh_check("eh_no_eh_control", eh_no_eh_control(0), 1);
    return eh_failures == 0 ? 0 : 1;
}
