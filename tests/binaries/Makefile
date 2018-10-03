CC              =       gcc
DEBUG           =       1
CFLAGS          +=      -Wall
SOURCES         =       $(wildcard *.c)
COMPILED        =       $(SOURCES:.c=.o)
LINKED          =       $(SOURCES:.c=.out)
LDFLAGS         =
EXTRA_FLAGS	=

ifeq ($(TARGET), x86)
CFLAGS          +=      -m32
endif

ifeq ($(DEBUG), 1)
CFLAGS          +=      -DDEBUG=1 -ggdb -O0
else
CFLAGS          +=      -O1
endif


.PHONY : all clean

all: $(LINKED)


%.out : %.c
	@echo "[+] Building '$@'"
	@$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ $? $(LDFLAGS)

clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(COMPILED) $(LINKED)

format-string-helper.out: EXTRA_FLAGS := -Wno-format-security

checksec-no-canary.out: EXTRA_FLAGS := -fno-stack-protector

# NOTE: If compiling with a older GCC (older than 4.8.4 maybe?) then use `-fno-pie`
checksec-no-pie.out: EXTRA_FLAGS := -no-pie

checksec-no-nx.out: EXTRA_FLAGS := -z execstack

pattern.out: EXTRA_FLAGS := -D_FORTIFY_SOURCE=0 -fno-stack-protector

canary.out: EXTRA_FLAGS := -fstack-protector-all

default.out: EXTRA_FLAGS := -fstack-protector-all -fpie -pie
