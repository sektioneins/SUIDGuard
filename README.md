SUIDGuard - A kernel extension adding mitigations to OS X to make exploitation harder

Copyright (c) Stefan Esser / SektionEins GmbH, 2015. All rights reserved.  
stefan.esser@sektioneins.de - https://www.sektioneins.de/

**OFFICIAL WEBSITE**
If you came here from a media article please checkout the official website https://www.suidguard.com 

## About
SUIDGuard is a TrustedBSD kernel driver that implements several mitigations to protect
against weaknesses in the operating system usually abused in exploits.

  - protects SUID/SGID root binaries from DYLD_ environment variables
    by overwriting the string DYLD_ with XYLD_
  - protects the O_APPEND flag usually used when opening e.g. logfiles 
    from being disabled by someone with credentials that are different 
	from those used to open the file
  - disallows execution of executables without a __PAGEZERO segment
    (stops NULL page exploits like e.g. tpwn)
	
Tested with OS X Yosemite 10.10.5.

## Downloads for OSX 10.10.x

**ATTENTION**: 
For ease of installation an autoloading version of this extension including 
a signed installer is available at

DMG: https://www.suidguard.com/downloads/SUIDGuardNG-106.dmg

PKG: https://www.suidguard.com/downloads/SUIDGuardNG-106.pkg

(source code on GitHub might not always be latest)

**WARNING**: These downloads are meant for OSX 10.10 only! Please **uninstall before upgrading to 10.10.4**!! (see issue #12 on details how to manually remove the extension after crash-on-boot)

## Downloads for OSX 10.11

TBD
