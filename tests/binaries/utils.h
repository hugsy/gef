#include <signal.h>

/**
 * Provide an cross-architecture way to break into the debugger.
 * On some architectures, we resort to `raise(SIGINT)` which is not
 * optimal, as it adds an extra frame to the stack.
 */

/* Intel x64 */
#if defined(__x86_64__)
#define DebugBreak() __asm__("int $3")

/* Intel x32 */
#elif defined(__i386) || defined(i386) || defined(__i386__)
#define DebugBreak() __asm__("int $3")

/* AARCH64 */
#elif defined(__aarch64__)
#define DebugBreak() { raise( SIGINT ) ; }

/* ARM */
#elif defined(__arm__) || defined(__arm)
#define DebugBreak() { raise( SIGINT ) ; }

/* MIPS */
#elif defined(mips) || defined(__mips__) || defined(__mips)
#define DebugBreak() __builtin_trap()

/* PowerPC */
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
#define DebugBreak() __builtin_trap()

/* the rest */
#else
#error "Unsupported architecture"
#endif
