stub.out: stub.c
	gcc -nostdlib -nostartfiles -include ../nolibc/nolibc.h -static -Os -fcf-protection=none \
		-Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none -Wl,-z,noexecstack \
		stub.c -o stub.out
	./gen.sh
