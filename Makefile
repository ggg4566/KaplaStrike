CC_64=x86_64-w64-mingw32-gcc
NASM=nasm
CFLAGS_64=-DWIN_X64 -shared -Wall -Wno-pointer-arith

all: exe

bin:
	mkdir -p bin

# ════════════════════════════════════════════════════════════════════
# EXE to Shellcode Loader
# Convert console EXE to position-independent shellcode
# Execution via WsmSvc sacrificial DLL module overloading
# 
# Usage: 
#   make exe
#   make exe-build EXE_PATH=/path/to/app.exe CMDLINE="arg1 arg2"
# ════════════════════════════════════════════════════════════════════

exe: bin
	@echo "[*] Compiling EXE loader (x64)..."
	$(CC_64) $(CFLAGS_64) -c src/loader.c -o bin/loader.x64.o
	
	@echo "[*] Compiling hooks.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/hooks/hooks.c -o bin/hooks.x64.o
	
	@echo "[*] Compiling spoof.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/draugr/spoof.c -o bin/spoof.x64.o

	@echo "[*] Compiling cleanup.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/sleep/cleanup.c -o bin/cleanup.x64.o

	@echo "[*] Compiling cfg.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/cfg/cfg.c -o bin/cfg.x64.o

	@echo "[+] EXE loader build complete!"
	@echo "[*] Output: bin/loader.x64.o"
	@echo "[*] Next: Use build_exe_shellcode.sh to convert EXE -> shellcode"

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f bin/loader*.x64.o
	rm -f bin/hooks*.x64.o
	rm -f bin/draugr*.x64.o
	rm -f bin/draugr*.x64.bin
	rm -f bin/pico*.x64.o
	rm -f bin/mask*.x64.o
	rm -f bin/spoof*.x64.o
	rm -f bin/cleanup*.x64.o
	rm -f bin/cfg*.x64.o
	rm -f bin/*.shellcode
	rm -f bin/*.hex

	@echo "[+] Clean complete!"

.PHONY: all exe clean
