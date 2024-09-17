stub.out: stub.c
	gcc -nostdlib -nostartfiles -include ../nolibc/nolibc.h -static -Os -fcf-protection=none \
		-Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none -Wl,-Tminimal.ld \
		stub.c -o stub.out
	# sections do nothing since we're static, and they add like 1k bytes,
	# but objcopy is weird dependency and the flags for stripping sections
	# changed in a recent version, so just don't do this by default
	#objcopy --strip-section-headers stub.out
	./gen.sh
