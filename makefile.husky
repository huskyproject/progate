#!/usr/bin/make -f

# include Husky-Makefile-Config
include ../huskymak.cfg

ifeq ($(DEBUG), 1)
  POPT = -d$(OSTYPE) -Fu$(INCDIR) -dDEBUG
else
  POPT = -d$(OSTYPE) -Fu$(INCDIR) -dRELEASE
endif


PASFILES = crc32.pas generalp.pas inifile.pas log.pas mkdos.pas mkffile.pas mkfile.pas mkglobt.pas mkmisc.pas mkmsgabs.pas mkmsgezy.pas mkmsgfid.pas mkmsghud.pas mkmsgjam.pas mkmsgsqu.pas mkopen.pas mkstring.pas progate.pas types.pas

all: progate$(EXE)

progate$(EXE): $(PASFILES)
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

