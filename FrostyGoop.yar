rule FrostyGoop {
meta:
    description = "rule to detect FrostyGoop"
    author = "ShadowStackRe.com"
    date = "2024-09-20"
    Rule_Version = "v1"
    malware_type = "ICS"
    malware_family = "FrostyGoop"
    License = "MIT License, https://opensource.org/license/mit/"
strings:
        $cfgIP = "ip"
        $cfgInputTask = "input-task=[FILE.json]"
        $cfgInputList = "input-list=[FILE.json]"
        $cfgInputTarget = "input-target=[FILE.json]"
        $cfgCycle = "cycle info=[FILE.json]"
        $cfgOutput = "output=[FILE.json]"
        $cfgMode = "read-all,\nread address=[Address int]"
        $strSkip = "Skip"
condition:
        uint16(0) == 0x5a4d and all of them
}

// Repo found in: https://github.com/filescanio/fsYara/blob/3d2ddd3c5e11c1eae6817e439f092a6d30ff954d/executable/PE-ELF/generic/mal_go_modbus.yar
rule MAL_Go_Modbus_Jul24_1 : hardened limited
{
	meta:
		description = "Detects characteristics reported by Dragos for FrostyGoop ICS malware"
		author = "Florian Roth"
		reference = "https://hub.dragos.com/hubfs/Reports/Dragos-FrostyGoop-ICS-Malware-Intel-Brief-0724_.pdf"
		date = "2024-07-23"
		modified = "2024-07-24"
		score = 75
		hash1 = "5d2e4fd08f81e3b2eb2f3eaae16eb32ae02e760afc36fa17f4649322f6da53fb"

	strings:
		$a1 = {47 6f 20 62 75 69 6c 64}
		$sa1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 72 6f 6c 66 6c 2f 6d 6f 64 62 75 73}
		$sb1 = {6d 61 69 6e 2e 54 61 73 6b 4c 69 73 74 2e 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64}
		$sb2 = {6d 61 69 6e 2e 54 61 72 67 65 74 4c 69 73 74 2e 67 65 74 54 61 72 67 65 74 49 70 4c 69 73 74}
		$sb3 = {6d 61 69 6e 2e 54 61 73 6b 4c 69 73 74 2e 67 65 74 54 61 73 6b 49 70 4c 69 73 74}
		$sb4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 61 69 6e 2e 43 79 63 6c 65 49 6e 66 6f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 30MB and ( $sa1 and 3 of ( $sb* ) ) or 4 of them
}

// Repo found in: https://github.com/roadwy/DefenderYara/blob/95d7a68c353d805e68276acd6cf75ec5db4703b4/Trojan/Win64/FrostyGoop/Trojan_Win64_FrostyGoop_AFR_MTB.yar#L2
rule Trojan_Win64_FrostyGoop_AFR_MTB{
	meta:
		description = "Trojan:Win64/FrostyGoop.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 6d 00 48 8d 05 a9 7a 07 00 48 89 44 24 50 48 c7 44 24 58 08 00 00 00 48 8d 0d 57 73 07 00 48 89 4c 24 60 48 c7 44 24 68 07 00 00 00 48 8d 0d f4 69 07 00 48 89 4c 24 70 48 c7 44 24 78 03 00 00 00 48 8d 0d 3f 72 07 00 48 89 8c 24 80 00 00 00 48 c7 84 24 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

// Repo found in: https://github.com/ps-interactive/frostygoop-lab/blob/main/pe_golang.yara
rule pe_golang {
    meta:
        author = "The Cyber Yeti"
        description = "Detect PE files written in GoLang"

    strings:
        $go_build_inf = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A } //0xFF 0x20 Go buildinf:
        $go_build_id = { FF 20 47 6F 20 62 75 69 6C 64 20 49 44 3A 20 } //0xFF 0x20 Go build ID:<SPACE>
        $symtab = ".symtab"

    condition:
        (uint16(0) == 0x5a4d) and any of them
}
