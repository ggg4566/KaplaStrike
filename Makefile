CC_64=x86_64-w64-mingw32-gcc
CFLAGS_64=-DWIN_X64 -shared -Wall -Wno-pointer-arith

all: exe

bin:
	mkdir -p bin

# ════════════════════════════════════════════════════════════════════════════
# KaplaStrike - Console EXE to Shellcode Converter
#
# Converts Windows console EXE files to position-independent shellcode
# that executes via WsmSvc sacrificial DLL module overloading.
#
# Usage:
#   make exe
#   ./build_exe_shellcode.sh /path/to/app.exe "arg1 arg2"
# ════════════════════════════════════════════════════════════════════════════

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
	@echo "[*] Next: ./build_exe_shellcode.sh /path/to/target.exe \"args\""

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f bin/*.x64.o
	rm -f bin/*.bin
	rm -f bin/*.hex
	@echo "[+] Clean complete!"

.PHONY: all exe clean
