#!/usr/bin/make -f

# include Husky-Makefile-Config
include ../huskymak.cfg

ifeq ($(DEBUG), 1)
ifeq ($(PC), ppc386)
  POPT = -d$(OSTYPE) -Fu$(INCDIR) -dDEBUG
  PCOPT = $(POPT)
else
  POPT = -D$(OSTYPE) -DDEBUG
  PCOPT = $(POPT) -c
endif
else
ifeq ($(PC), ppc386)
  POPT = -d$(OSTYPE) -Fu$(INCDIR) -dRELEASE
  PCOPT = $(POPT)
else
  POPT = -D$(OSTYPE) -DRELEASE
  PCOPT = $(POPT) -c
endif
endif


all: progate$(EXE)

%$(OBJ): %.pas
	$(PC) $(PCOPT) $*.pas

generalp$(OBJ): types$(OBJ)

progate$(EXE): crc32$(OBJ) generalp$(OBJ) inifile$(OBJ) log$(OBJ) mkdos$(OBJ) \
               mkffile$(OBJ) mkglobt$(OBJ) mkmisc$(OBJ) mkmsgabs$(OBJ) \
               mkmsgezy$(OBJ) mkmsgfido$(OBJ) mkmsghud$(OBJ) mkmsgjam$(OBJ) \
               mkmsgsqu$(OBJ) mkopen$(OBJ) mkstring$(OBJ) types$(OBJ)
	$(PC) $(POPT) progate.pas

clean:
	-$(RM) *$(OBJ)
	-$(RM) *$(LIB)
	-$(RM) *$(TPU)
	-$(RM) *~

distclean: clean
	-$(RM) progate$(EXE)

install:
	$(INSTALL) $(IBOPT) progate$(EXE) $(BINDIR)
