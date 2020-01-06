default-target: all
default-target: .PHONY
.PHONY:

BIBTEX = bibtex
PDFLATEX = pdflatex

_CPPFLAGS = $(CPPFLAGS) \
	-Itweetnacl \
	-Icrypto_aead/salsa20daence/ref \
	-DDAENCE_GENERATE_KAT

all: .PHONY
all: daence.pdf
all: check

check: .PHONY

clean: .PHONY

daence.pdf: daence.bib
daence.pdf: daence.tex
daence.pdf: testvector.c
daence.pdf: testvector.out
daence.pdf: tweetdaence.c
	$(PDFLATEX) \\nonstopmode\\input daence
	$(BIBTEX) daence
	$(PDFLATEX) \\nonstopmode\\input daence
	$(BIBTEX) daence
	$(PDFLATEX) \\nonstopmode\\input daence
	$(PDFLATEX) \\nonstopmode\\input daence
	$(PDFLATEX) \\nonstopmode\\input daence

clean: clean-daence.pdf
clean-daence.pdf: .PHONY
	-rm -f daence.aux
	-rm -f daence.bbl
	-rm -f daence.blg
	-rm -f daence.brf
	-rm -f daence.log
	-rm -f daence.out
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

SRCS_t_daence = \
	crypto_aead/salsa20daence/ref/salsa20daence.c \
	t_daence.c \
	tweetnacl/tweetnacl.c \
	# end of SRCS_t_daence
t_daence: $(SRCS_t_daence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_t_daence:.c=.o)

check: check-daence
check-daence: .PHONY
check-daence: t_daence
	./t_daence

clean: clean-daence
clean-daence: .PHONY
	-rm -f t_daence
	-rm -f $(SRCS_t_daence:.c=.o)

tweetnacl/tweetnacl.o: tweetnacl/tweetnacl.c
	$(CC) -c -o $@ $(CFLAGS) $(_CPPFLAGS) -Wno-sign-compare \
		tweetnacl/tweetnacl.c

SRCS_t_tweetdaence = \
	t_tweetdaence.c \
	tweetdaence.c \
	tweetnacl/tweetnacl.c \
	# end of SRCS_t_tweetdaence
t_tweetdaence: $(SRCS_t_tweetdaence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_t_tweetdaence:.c=.o)

check: check-tweetdaence
check-tweetdaence: .PHONY
check-tweetdaence: t_tweetdaence
	./t_tweetdaence

clean: clean-tweetdaence
clean-tweetdaence: .PHONY
	-rm -f t_tweetdaence
	-rm -f $(SRCS_t_tweetdaence:.c=.o)

.SUFFIXES:
.SUFFIXES: .c
.SUFFIXES: .o

.c.o:
	$(CC) -o $@ $(CFLAGS) $(_CPPFLAGS) -c $<

crypto_aead/salsa20daence/ref/salsa20daence.o: crypto_aead/salsa20daence/ref/salsa20daence.h
crypto_aead/salsa20daence/ref/salsa20daence.o: tweetnacl/crypto_core_hsalsa20.h
crypto_aead/salsa20daence/ref/salsa20daence.o: tweetnacl/crypto_onetimeauth_poly1305.h
crypto_aead/salsa20daence/ref/salsa20daence.o: tweetnacl/crypto_stream_xsalsa20.h
crypto_aead/salsa20daence/ref/salsa20daence.o: tweetnacl/crypto_verify_32.h
crypto_aead/salsa20daence/ref/salsa20daence.o: tweetnacl/tweetnacl.h
daence.o: daence.h
daence.o: tweetnacl/tweetnacl.h
t_daence.o: crypto_aead/salsa20daence/ref/salsa20daence.h
t_tweetdaence.o: tweetdaence.h
tweetdaence.o: tweetdaence.h
tweetdaence.o: tweetnacl/tweetnacl.h
tweetnacl/tweetnacl.o: tweetnacl/tweetnacl.h
