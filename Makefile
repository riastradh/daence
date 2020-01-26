default-target: all
default-target: .PHONY
.PHONY:

BIBTEX = bibtex
PDFLATEX = pdflatex

_CFLAGS = $(CFLAGS) -Werror -MMD -MF $*.d
_CPPFLAGS = $(CPPFLAGS) \
	-Itweetnacl \
	-DDAENCE_GENERATE_KAT

all: .PHONY
all: daence.pdf
all: diagdaence.pdf
all: diagdice.pdf
all: diagpoly13052.pdf
all: check

check: .PHONY

clean: .PHONY

daence.pdf: daence.bib
daence.pdf: daence.tex
daence.pdf: kat_salsa20daence.c
daence.pdf: kat_salsa20daence.out
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

diagdaence.pdf: daence.tikz
diagdaence.pdf: diagdaence.tex
diagdaence.pdf: palette.def
	$(PDFLATEX) \\nonstopmode\\input diagdaence
clean: clean-diagdaence.pdf
clean-diagdaence.pdf: .PHONY
	-rm -f diagdaence.aux
	-rm -f diagdaence.log
	-rm -f diagdaence.pdf

diagdice.pdf: diagdice.tex
diagdice.pdf: dice.tikz
diagdice.pdf: palette.def
	$(PDFLATEX) \\nonstopmode\\input diagdice
clean: clean-diagdice.pdf
clean-diagdice.pdf: .PHONY
	-rm -f diagdice.aux
	-rm -f diagdice.log
	-rm -f diagdice.pdf

diagpoly13052.pdf: diagpoly13052.tex
diagpoly13052.pdf: poly13052.tikz
	$(PDFLATEX) \\nonstopmode\\input diagpoly13052
clean: clean-diagpoly13052.pdf
clean-diagpoly13052.pdf: .PHONY
	-rm -f diagpoly13052.aux
	-rm -f diagpoly13052.log
	-rm -f diagpoly13052.pdf

check: check-kat_chachadaence
check-kat_chachadaence: .PHONY
check-kat_chachadaence: kat_chachadaence.exp
check-kat_chachadaence: kat_chachadaence.out
	diff -u kat_chachadaence.exp kat_chachadaence.out

kat_chachadaence.out: kat_chachadaence
	./kat_chachadaence > $@.tmp && mv -f $@.tmp $@
clean: clean-kat_chachadaence.out
clean-kat_chachadaence.out: .PHONY
	-rm -rf kat_chachadaence.out

SRCS_kat_chachadaence = \
	kat_chachadaence.c \
	# end of SRCS_kat_chachadaence
DEPS_kat_chachadaence = $(SRCS_kat_chachadaence:.c=.d)
-include $(DEPS_kat_chachadaence)
LIBS_kat_chachadaence = \
	-lsodium \
	# end of LIBS_kat_chachadaence
kat_chachadaence: $(SRCS_kat_chachadaence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_kat_chachadaence:.c=.o) \
		$(LIBS_kat_chachadaence)
clean: clean-kat_chachadaence
clean-kat_chachadaence: .PHONY
	-rm -f kat_chachadaence
	-rm -f $(SRCS_kat_chachadaence:.c=.o)
	-rm -f $(SRCS_kat_chachadaence:.c=.d)

check: check-kat_salsa20daence
check-kat_salsa20daence: .PHONY
check-kat_salsa20daence: kat_salsa20daence.exp
check-kat_salsa20daence: kat_salsa20daence.out
	diff -u kat_salsa20daence.exp kat_salsa20daence.out

kat_salsa20daence.out: kat_salsa20daence
	./kat_salsa20daence > $@.tmp && mv -f $@.tmp $@
clean: clean-kat_salsa20daence.out
clean-kat_salsa20daence.out: .PHONY
	-rm -rf kat_salsa20daence.out

SRCS_kat_salsa20daence = \
	kat_salsa20daence.c \
	# end of SRCS_kat_salsa20daence
DEPS_kat_salsa20daence = $(SRCS_kat_salsa20daence:.c=.d)
-include $(DEPS_kat_salsa20daence)
LIBS_kat_salsa20daence = \
	-lsodium \
	# end of LIBS_kat_salsa20daence
kat_salsa20daence: $(SRCS_kat_salsa20daence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_kat_salsa20daence:.c=.o) \
		$(LIBS_kat_salsa20daence)
clean: clean-kat_salsa20daence
clean-kat_salsa20daence: .PHONY
	-rm -f kat_salsa20daence
	-rm -f $(SRCS_kat_salsa20daence:.c=.o)
	-rm -f $(SRCS_kat_salsa20daence:.c=.d)

SRCS_t_chachadaence = \
	chachadaence.c \
	t_chachadaence.c \
	tweetnacl/tweetnacl.c \
	# end of SRCS_t_chachadaence
DEPS_t_chachadaence = $(SRCS_t_chachadaence:.c=.d)
-include $(DEPS_t_chachadaence)
LIBS_t_chachadaence = \
	-lsodium \
	# end of LIBS_t_chachadaence
t_chachadaence: $(SRCS_t_chachadaence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_t_chachadaence:.c=.o) \
		$(LIBS_t_chachadaence)

check: check-chachadaence
check-chachadaence: .PHONY
check-chachadaence: t_chachadaence
	./t_chachadaence

clean: clean-chachadaence
clean-chachadaence: .PHONY
	-rm -f t_chachadaence
	-rm -f $(SRCS_t_chachadaence:.c=.o)
	-rm -f $(SRCS_t_chachadaence:.c=.d)

SRCS_t_salsa20daence = \
	salsa20daence.c \
	t_salsa20daence.c \
	tweetnacl/tweetnacl.c \
	# end of SRCS_t_salsa20daence
DEPS_t_salsa20daence = $(SRCS_t_salsa20daence:.c=.d)
-include $(DEPS_t_salsa20daence)
t_salsa20daence: $(SRCS_t_salsa20daence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_t_salsa20daence:.c=.o)

check: check-salsa20daence
check-salsa20daence: .PHONY
check-salsa20daence: t_salsa20daence
	./t_salsa20daence

clean: clean-salsa20daence
clean-salsa20daence: .PHONY
	-rm -f t_salsa20daence
	-rm -f $(SRCS_t_salsa20daence:.c=.o)
	-rm -f $(SRCS_t_salsa20daence:.c=.d)

tweetnacl/tweetnacl.o: tweetnacl/tweetnacl.c
	$(CC) -c -o $@ $(_CFLAGS) $(_CPPFLAGS) -Wno-sign-compare \
		tweetnacl/tweetnacl.c

SRCS_t_tweetdaence = \
	t_tweetdaence.c \
	tweetdaence.c \
	tweetnacl/tweetnacl.c \
	# end of SRCS_t_tweetdaence
DEPS_t_tweetdaence = $(SRCS_t_tweetdaence:.c=.d)
-include $(DEPS_t_tweetdaence)
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
	-rm -f $(SRCS_t_tweetdaence:.c=.d)

.SUFFIXES:
.SUFFIXES: .c
.SUFFIXES: .o

.c.o:
	$(CC) -c -o $@ $(_CFLAGS) $(_CPPFLAGS) $<
