stub.out: stub.c
	gcc -nostdlib -nostartfiles -include ../nolibc/nolibc.h -static -Os -fcf-protection=none \
		-Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none -Wl,-Tminimal.ld \
		stub.c -o stub.out
	objcopy --strip-section-headers stub.out
	./gen.sh
