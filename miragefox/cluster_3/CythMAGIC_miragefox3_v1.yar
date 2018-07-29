rule CythMAGIC_miragefox3_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "e72eacb0931ba342b54f0a7cab36a98027e83be9"
	size_of_cluster = "2"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_b6b3f579bf8301a9dc04052c7c8a942b = { 55 8B EC 51 53 56 8B 75 18 57 33 FF 33 C0 B9 00 01 00 00 88 04 30 40 3B C1 7C F8 89 7D 18 89 7D FC 8B C7 8A 1C 37 99 F7 7D 14 8B 45 08 8B 7D 18 0F BE 14 02 0F B6 C3 03 FA 03 C7 8B F9 99 F7 FF 8B 7D FC 89 55 18 8D 04 32 8A 14 32 88 14 37 47 3B F9 88 18 89 7D FC 7C C8 5F 5E 5B C9 C3 }
	$_c916eaa03ce87b3e28e1d315358f8129 = { 55 8B EC 8B 45 08 83 E8 00 74 07 48 74 04 33 C0 5D C3 FF 75 14 FF 75 10 FF 75 0C E8 ?? ?? ?? ?? 59 50 FF 75 0C E8 2C FF FF FF 83 C4 10 6A 01 58 5D C3 }
	$_0a175f9037e61d9125eb1b0ada6c3ab7 = { 56 BE ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B 54 24 08 8B 02 85 C0 74 13 8B 88 0C 88 00 00 85 C9 74 09 50 89 0A E8 ?? ?? ?? ?? 59 56 FF 15 ?? ?? ?? ?? 5E C3 }
	$_9ca27f16ddfc5abd6da4ac221940797b = { 55 8B EC 51 8D 45 FC 56 8B 35 ?? ?? ?? ?? 83 65 FC 00 50 FF 75 08 6A 26 6A 00 FF D6 85 C0 74 25 83 7D FC 00 76 1F 57 FF 75 FC E8 ?? ?? ?? ?? 8B F8 59 8D 45 FC 50 57 6A 26 6A 00 FF D6 83 3F 01 5F 75 02 33 C0 5E C9 C2 04 00 }
	$_5a3b2f1a29e4e7eb1eab30f509436e54 = { 8B 44 24 08 8B 54 24 04 56 33 F6 33 C9 83 F8 01 76 1A 53 57 8B F8 D1 EF 33 DB 8A 3C 0A 8A 5C 0A 01 03 F3 41 41 48 48 4F 75 EE 5F 5B 85 C0 76 09 0F B6 04 11 C1 E0 08 03 F0 B8 00 00 FF FF 85 F0 74 0F 8B CE 81 E6 FF FF 00 00 C1 E9 10 03 F1 EB ED 8B C6 5E F7 D0 C3 }
 condition:
        all of them // out of 5
}
