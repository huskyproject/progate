#!/usr/bin/make -f
PASOPT = -dLinux

PASFILES = crc32.pas generalp.pas inifile.pas log.pas mkdos.pas mkffile.pas mkfile.pas mkglobt.pas mkmisc.pas mkmsgabs.pas mkmsgezy.pas mkmsgfid.pas mkmsghud.pas mkmsgjam.pas mkmsgsqu.pas mkopen.pas mkstring.pas progate.pas types.pas

all: debug

progate: $(PASFILES)
	ppc386 $(PASOPT) progate.pas

debug:
	ppc386 $(PASOPT) -dDEBUG progate.pas

release:
	ppc386 $(PASOPT) -dRELEASE progate.pas

