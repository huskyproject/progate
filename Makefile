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
               mkmsgezy$(OBJ) mkmsgfid$(OBJ) mkmsghud$(OBJ) mkmsgjam$(OBJ) \
               mkmsgsqu$(OBJ) mkopen$(OBJ) mkstring$(OBJ) types$(OBJ)
	$(PC) $(POPT) progate.pas

clean:
	-$(RM) $(RMOPT) *$(OBJ)
	-$(RM) $(RMOPT) *$(LIB)
	-$(RM) $(RMOPT) *$(TPU)
	-$(RM) $(RMOPT) *~

distclean: clean
	-$(RM) $(RMOPT) progate$(EXE)

install:
	$(INSTALL) $(IBOPT) progate$(EXE) $(BINDIR)

uninstall:
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)progate$(EXE)

