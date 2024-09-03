.phony: all
all: main.o
	objdump -Mintel -d main.o

main.o: main.asm
	nasm -felf64 main.asm -o main.o

.phony: clean
clean:
	rm -f main.o
