BIN=./bin/proyecto1
B=proyecto1

SRCDIR=./src/
INCLDIR=./incl/

.PHONY: doc

all: build run clean

build:
	g++ -g -I $(INCLDIR) -o $(BIN) $(SRCDIR)main.cpp

run:
	cd bin && ./$(B)

clean:
	rm -rf $(BIN)

doc:
	doxygen Doxyfile

