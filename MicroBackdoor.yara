import "pe"

rule MicroBackdoor
{
	meta:
		author= "Silas Cutler"
		description = "Detection for MicroBackdoor (https://github.com/Cr4sh/MicroBackdoor)"
		version = "0.1"
	strings:
		$ = "%s|%s|%d|%s|%d|%d" wide
		$ = "chcp 65001 > NUL & " wide
		$ = "cmd.exe /C \"%s%s\"" wide
		$ = "0x%I64x %s" wide
		$ = "CONNECT %s:%d HTTP/1.0"
	condition:
		all of them	and pe.section_index(".conf") >= 0
}
