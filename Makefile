CC_64=x86_64-w64-mingw32-gcc
NASM=nasm
CFLAGS_64=-DWIN_X64 -shared -Wall -Wno-pointer-arith
CFLAGS_UNIVERSAL=-DWIN_X64 -shared -Wall -Wno-pointer-arith -DUNIVERSAL_DLL_MODE=1

all: x64

bin:
	mkdir -p bin

# ═══════════════════════════════════════════════════════════════════════════
# Beacon 版本（原始功能，默认编译目标）
# 编译：make x64
# ═══════════════════════════════════════════════════════════════════════════
x64: bin
	@echo "[*] Compiling Beacon-specific loader (x64)..."
	$(CC_64) $(CFLAGS_64) -c src/loader.c -o bin/loader.x64.o
	
	@echo "[*] Compiling hooks.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/hooks/hooks.c -o bin/hooks.x64.o
	
	@echo "[*] Compiling spoof.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/draugr/spoof.c -o bin/spoof.x64.o

	@echo "[*] Compiling mask.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/sleep/mask.c -o bin/mask.x64.o

	@echo "[*] Compiling pico.x64.o..."
	$(CC_64) $(CFLAGS_64) -c src/sleep/pico.c -o bin/pico.x64.o

	@echo "[*] Compiling draugr.x64.bin..."
	$(NASM) src/draugr/draugr.asm -o bin/draugr.x64.bin

	@echo "[*] Compiling cleanup.x64.bin..."
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/sleep/cleanup.c  -o bin/cleanup.x64.o

	@echo "[*] Compiling cfg.x64.bin..."
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/cfg/cfg.c  -o bin/cfg.x64.o

	@echo "[+] Beacon build complete!"

# ═══════════════════════════════════════════════════════════════════════════
# 通用 DLL 版本（支持任意标准 Windows DLL）
# 编译：make universal
# ═══════════════════════════════════════════════════════════════════════════
universal: bin
	@echo "[*] Compiling Universal DLL loader (x64)..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/loader.c -o bin/loader_universal.x64.o
	
	@echo "[*] Compiling hooks_universal.x64.o..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/hooks/hooks.c -o bin/hooks_universal.x64.o
	
	@echo "[*] Compiling spoof_universal.x64.o..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/draugr/spoof.c -o bin/spoof_universal.x64.o

	@echo "[*] Compiling mask_universal.x64.o..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/sleep/mask.c -o bin/mask_universal.x64.o

	@echo "[*] Compiling pico_universal.x64.o..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/sleep/pico.c -o bin/pico_universal.x64.o

	@echo "[*] Compiling draugr_universal.x64.bin..."
	$(NASM) src/draugr/draugr.asm -o bin/draugr_universal.x64.bin

	@echo "[*] Compiling cleanup_universal.x64.bin..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/sleep/cleanup.c -o bin/cleanup_universal.x64.o

	@echo "[*] Compiling cfg_universal.x64.bin..."
	$(CC_64) $(CFLAGS_UNIVERSAL) -c src/cfg/cfg.c -o bin/cfg_universal.x64.o

	@echo "[+] Universal DLL build complete!"

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

	@echo "[+] Clean complete!"

.PHONY: all x64 universal clean
