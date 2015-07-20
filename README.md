SUIDGuard - A kernel extension adding mitigations to protect SUID/SGID binaries

Copyright (c) Stefan Esser / SektionEins GmbH, 2015. All rights reserved.  
stefan.esser@sektioneins.de - https://www.sektioneins.de/

SUIDGuard is a TrustedBSD kernel driver that implements several mitigations to protects
against weaknesses usually involving SUID/SGID binaries.

  - protects SUID/SGID root binaries from DYLD_ environment variables
    by overwriting the string DYLD_ with XYLD_
  - protects the O_APPEND flag usually used when opening e.g. logfiles 
    from being disabled by someone with credentials that are different 
	from those used to open the file
	
Tested with OS X Yosemite 10.10.4.

Regards,
Stefan Esser
