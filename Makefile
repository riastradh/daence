default-target: all
default-target: .PHONY
.PHONY:

BIBTEX = bibtex
PDFLATEX = pdflatex
PYTHON = python3

_CFLAGS = $(CFLAGS) -Werror -MMD -MF $(@:.o=.d)
_CPPFLAGS = $(CPPFLAGS) \
	-Itweetnacl \
	-DDAENCE_GENERATE_KAT

KAT2JSON = { awk ' \
		BEGIN	{ x = ""; n = 0 } \
		$$0 ~ /^  */ { sub(/^  */, ""); x = x $$0; next } \
			{ if (n) print x; x = $$0; n = 1 } \
		END	{ if (n) print x } \
	' | awk -F= ' \
		BEGIN	{ printf("[\n    {\n"); n = 0; c = 0 } \
		NF == 0	{ n = 1; next } \
			{ if (n) \
			    printf("\n    },\n    {\n"); \
			  else if (c) \
			    printf(",\n"); \
			  printf("        \"%s\": \"%s\"", $$1, $$2); \
			  c = 1; n = 0 } \
		END	{ printf("\n    }\n]\n") } \
	'; }

all: .PHONY
all: check
all: daence.pdf
all: diagdaence.pdf
all: diagdeuce.pdf
all: diagpoly13052.pdf
all: js/kat_salsa20daence.json

check: .PHONY

clean: .PHONY

daence.pdf: adv.tex
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

adv.tex: adv.py
	$(PYTHON) adv.py > $@.tmp && mv -f $@.tmp $@

clean: clean-adv.tex
clean-adv.tex: .PHONY
	-rm -f adv.tex
	-rm -f adv.tex.tmp

diagdaence.pdf: daence.tikz
diagdaence.pdf: diagdaence.tex
diagdaence.pdf: palette.def
	$(PDFLATEX) \\nonstopmode\\input diagdaence
clean: clean-diagdaence.pdf
clean-diagdaence.pdf: .PHONY
	-rm -f diagdaence.aux
	-rm -f diagdaence.log
	-rm -f diagdaence.pdf

diagdeuce.pdf: diagdeuce.tex
diagdeuce.pdf: deuce.tikz
diagdeuce.pdf: palette.def
	$(PDFLATEX) \\nonstopmode\\input diagdeuce
clean: clean-diagdeuce.pdf
clean-diagdeuce.pdf: .PHONY
	-rm -f diagdeuce.aux
	-rm -f diagdeuce.log
	-rm -f diagdeuce.pdf

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

js/kat_salsa20daence.json: kat_salsa20daence.exp
	$(KAT2JSON) < kat_salsa20daence.exp > $@.tmp && mv -f $@.tmp $@
clean: clean-js/kat_salsa20daence.json
clean-js/kat_salsa20daence.json: .PHONY
	-rm -f js/kat_salsa20daence.json
	-rm -f js/kat_salsa20daence.json.tmp

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

SRCS_t_beardaence = \
	beardaence.c \
	t_beardaence.c \
	# end of SRCS_t_beardaence
DEPS_t_beardaence = $(SRCS_t_beardaence:.c=.d)
-include $(DEPS_t_beardaence)
LIBS_t_beardaence = \
	-lbearssl \
	# end of LIBS_t_beardaence
t_beardaence: $(SRCS_t_beardaence:.c=.o)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRCS_t_beardaence:.c=.o) \
		$(LIBS_t_beardaence)

check: check-beardaence
check-beardaence: .PHONY
check-beardaence: t_beardaence
	./t_beardaence

clean: clean-beardaence
clean-beardaence: .PHONY
	-rm -f t_beardaence
	-rm -f $(SRCS_t_beardaence:.c=.o)
	-rm -f $(SRCS_t_beardaence:.c=.d)

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
