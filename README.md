# MICore.PSHelper
A PowerShell module with helpful cmdlets for managing managing devices on MobileIron Core.

To install, create a subdirectory under the $env:PSModulePath directory named MICore.PSHelper and copy the MICore.PsHelper.psm1 file into that directory.  Then create a shortcut to open a MobileIron Powershell window with the command line:

powershell.exe -noExit -Command "& {Import-module MICore.PSHelper.psm1}"
