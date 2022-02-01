#include <signal.h>

/**
 * Provide an cross-architecture way to break into the debugger.
 * On some architectures, we resort to `raise(SIGINT)` which is not
 * optimal, as it adds an extra frame to the stack.
 */

/* Intel x64 (x86_64) */
#if defined(__x86_64__) || defined(__amd64__)
#define DebugBreak() __asm__("int $3")

/* Intel x32 (i686) */
#elif defined(__i386) || defined(i386) || defined(__i386__)
#define DebugBreak() __asm__("int $3")

/* AARCH64 (aarch64) */
#elif defined(__aarch64__)
#define DebugBreak() { raise( SIGINT ) ; }

/* ARM (armv7le*/
#elif defined(__arm__) || defined(__arm)
#define DebugBreak() { raise( SIGINT ) ; }

/* MIPS */
/* MIPS64 (mips64el) */
#elif defined(mips) || defined(__mips__) || defined(__mips)
#define DebugBreak() { raise( SIGINT ) ; }

/* PowerPC */
/* PowerPC64 (ppc64le) */
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
#define DebugBreak() { raise( SIGINT ) ; }

/* SPARC */
/* SPARC64 */
// #elif defined(__sparc) || defined(__sparc64__) || defined(__sparc__)
// #define DebugBreak() { raise( SIGINT ) ; }

/* RISC V */
#elif defined(__riscv)
#define DebugBreak() { raise( SIGINT ) ; }

/* the rest */
#else
#error "Unsupported architecture"
// #define DebugBreak() __builtin_trap()
#endif
