default-target: all
default-target: .PHONY
.PHONY:

BIBTEX = bibtex
PDFLATEX = pdflatex

all: .PHONY
all: daence.pdf

check: .PHONY

clean: .PHONY

daence.pdf: daence.bib
daence.pdf: daence.tex
daence.pdf: testvector.c
daence.pdf: testvector.exp
	$(PDFLATEX) \\nonstopmode\\input daence
	$(BIBTEX) daence
	$(PDFLATEX) \\nonstopmode\\input daence
	$(BIBTEX) daence
	$(PDFLATEX) \\nonstopmode\\input daence
	$(PDFLATEX) \\nonstopmode\\input daence
clean: clean-daence.pdf
clean-daence.pdf: .PHONY
	-rm -f daence.aux
	-rm -f daence.bbl
	-rm -f daence.blg
	-rm -f daence.brf
	-rm -f daence.log
	-rm -f daence.pdf

check: check-testvector
check-testvector: .PHONY
check-testvector: testvector.exp
check-testvector: testvector.out
	diff -u testvector.exp testvector.out

testvector.out: testvector
	./testvector > $@.tmp && mv -f $@.tmp $@
clean: clean-testvector.out
clean-testvector.out: .PHONY
	-rm -rf testvector.out

SRCS_testvector = \
	testvector.c \
	# end of SRCS_testvector
LIBS_testvector = \
	-lsodium \
	# end of LIBS_testvector
testvector: $(SRCS_testvector:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_testvector:.c=.o) \
		$(LIBS_testvector)
clean: clean-testvector
clean-testvector: .PHONY
	-rm -f testvector
	-rm -f $(SRCS_testvector:.c=.o)

SRCS_daence = \
	daence.c \
	tweetnacl.c \
	# end of SRCS_daence
daence: $(SRCS_daence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_daence:.c=.o)

check: check-daence
check-daence: .PHONY
check-daence: daence
	./daence

clean: clean-daence
clean-daence: .PHONY
	-rm -f daence
	-rm -f $(SRCS_daence:.c=.o)

tweetnacl.o: tweetnacl.c
	$(CC) -c -o $@ $(CFLAGS) $(CPPFLAGS) -Wno-sign-compare tweetnacl.c

daence.o: daence.h
daence.o: tweetnacl.h
tweetnacl.o: tweetnacl.h
