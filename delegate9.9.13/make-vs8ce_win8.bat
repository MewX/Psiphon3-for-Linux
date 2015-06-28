@SET VSINSTALLDIR=C:\Program Files (x86)\Microsoft Visual Studio 8
@SET VCINSTALLDIR=C:\Program Files (x86)\Microsoft Visual Studio 8\VC
@SET FrameworkDir=C:\WINDOWS\Microsoft.NET\Framework
@SET FrameworkVersion=v2.0.50727
@SET FrameworkSDKDir=C:\Program Files (x86)\Microsoft Visual Studio 8\SDK\v2.0
@if "%VSINSTALLDIR%"=="" goto error_no_VSINSTALLDIR
@if "%VCINSTALLDIR%"=="" goto error_no_VCINSTALLDIR

@echo Setting environment for using Microsoft Visual Studio 2005 x86 tools.

@rem
@rem Root of Visual Studio IDE installed files.
@rem
@set DevEnvDir=C:\Program Files (x86)\Microsoft Visual Studio 8\Common7\IDE

@set PATH=C:\Program Files (x86)\Microsoft Visual Studio 8\Common7\IDE;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\BIN;C:\Program Files (x86)\Microsoft Visual Studio 8\Common7\Tools;C:\Program Files (x86)\Microsoft Visual Studio 8\Common7\Tools\bin;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\PlatformSDK\bin;C:\Program Files (x86)\Microsoft Visual Studio 8\SDK\v2.0\bin;C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\VCPackages;%PATH%
@set INCLUDE=C:\Program Files (x86)\Microsoft Visual Studio 8\VC\ATLMFC\INCLUDE;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\INCLUDE;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\PlatformSDK\include;C:\Program Files (x86)\Microsoft Visual Studio 8\SDK\v2.0\include;%INCLUDE%
@set LIB=C:\Program Files (x86)\Microsoft Visual Studio 8\VC\ATLMFC\LIB;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\LIB;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\PlatformSDK\lib;C:\Program Files (x86)\Microsoft Visual Studio 8\SDK\v2.0\lib;%LIB%
@set LIBPATH=C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\ATLMFC\LIB

@goto end

:error_no_VSINSTALLDIR
@echo ERROR: VSINSTALLDIR variable is not set. 
@goto end

:error_no_VCINSTALLDIR
@echo ERROR: VCINSTALLDIR variable is not set. 
@goto end

:end



set VS8=C:\Program Files (x86)\Microsoft Visual Studio 8
set PATH=C:\Program Files (x86)\Microsoft Visual Studio 8\VC\ce\bin\x86_arm;C:\Program Files (x86)\Microsoft Visual Studio 8\Common7\IDE;%PATH%
set INCLUDE=C:\Program Files (x86)\Windows Mobile 6 SDK\PocketPC\Include\Armv4i;C:\Program Files (x86)\Microsoft Visual Studio 8\SmartDevices\SDK\PocketPC2003\Include
set LIB=C:\Program Files (x86)\Microsoft Visual Studio 8\SmartDevices\SDK\PocketPC2003\Lib\armv4;C:\Program Files (x86)\Microsoft Visual Studio 8\VC\ce\lib\armv4

@echo ///////////////////////////////////////////////////////////////////
@echo ////  VisualStudio 8 CE ////////////////////////////////////////////
@echo ///////////////////////////////////////////////////////////////////
NMAKE.EXE MAKE=NMAKE.EXE XDG=%XDG% XEMBED=%XEMBED% LDOPTS="-subsystem:windowsce -NODEFAULTLIB:"oldnames.lib" coredll.lib corelibc.lib ws2.lib" wince-dg.exe
