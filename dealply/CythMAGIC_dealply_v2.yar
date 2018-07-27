rule CythMAGIC_dealply_v2
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "b01ac08195e304aa4a9c1708ef20018edbb46466"
	size_of_cluster = "9"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_336a26da2586d6bd331e74711f3ce900 = { 55 8B EC 51 53 56 57 88 4D FF 8B FA 8B D8 8A 4D FF 8B D7 8B C3 E8 ?? ?? ?? ?? 8B F0 85 F6 75 0A 8B 45 08 E8 ?? ?? ?? ?? EB 1F 8B 45 08 50 8B C3 E8 ?? ?? ?? ?? 50 8B C7 E8 ?? ?? ?? ?? 8B D0 03 D6 8B C3 59 E8 ?? ?? ?? ?? 5F 5E 5B 59 5D C2 04 00 }
	$_9e677ca0d35bd4a0b32f0f85728a7473 = { 55 8B EC 83 C4 F8 53 56 57 88 4D FB 89 55 FC 8B F0 8B 7D 08 8A 4D FB 8B 55 FC 8B C6 E8 ?? ?? ?? ?? 8B D8 85 DB 75 0B 8B C7 8B D6 E8 ?? ?? ?? ?? EB 10 57 8B CB 49 BA 01 00 00 00 8B C6 E8 ?? ?? ?? ?? 5F 5E 5B 59 59 5D C2 04 00 }
	$_f1bb52a54a79776f385b1df4f0724431 = { 53 56 8B F0 80 3D ?? ?? ?? ?? ?? 75 0C C6 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 CB FF 8B C6 E8 ?? ?? ?? ?? 85 C0 7E 2B BA 01 00 00 00 33 C9 8A 4C 16 FF 33 CB 81 E1 FF 00 00 00 8B 0C 8D ?? ?? ?? ?? C1 EB 08 81 E3 FF FF FF 00 33 CB 8B D9 42 48 75 DA 81 E3 FF FF FF 7F 8B C3 5E 5B C3 }
	$_690d45fa4ce25f8d8b2f8dc5a2e2dc11 = { 80 EA 2B 74 0B 80 EA 02 74 10 FE CA 74 16 EB 20 25 ?? ?? ?? ?? 83 E8 30 EB 1B 25 FF 00 00 00 83 C0 4B EB 11 25 FF ?? ?? ?? 05 85 00 00 00 EB 05 25 FF 00 00 00 85 C0 7C 07 3D FF ?? ?? ?? 7E 05 B8 3F 00 00 00 C3 }
	$_ef3b224392ce4a9c13b72d0c24ac07f2 = { 55 8B EC 83 C4 F8 83 3D ?? ?? ?? ?? ?? 75 1B 8D 55 F8 8D 45 FC E8 ?? ?? ?? ?? 8B 45 FC A3 ?? ?? ?? ?? 8B 45 F8 A3 ?? ?? ?? ?? 8B 45 08 50 FF 15 ?? ?? ?? ?? 59 59 5D C2 04 00 }
	$_2a59eb4f14877220efaccad0bd3b7960 = { 53 56 81 C4 B0 FD FF FF 8B F0 33 DB 54 8B C6 E8 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 8B 00 FF D0 83 F8 FF 74 12 50 A1 ?? ?? ?? ?? 8B 00 FF D0 F6 04 24 10 75 02 B3 01 8B C3 81 C4 50 02 00 00 5E 5B C3 }
	$_2e68b08f5d8789c4c6f12cb6f4f24a48 = { 55 8B EC 83 C4 F8 83 3D ?? ?? ?? ?? ?? 75 1B 8D 55 F8 8D 45 FC E8 ?? ?? ?? ?? 8B 45 FC A3 ?? ?? ?? ?? 8B 45 F8 A3 ?? ?? ?? ?? 8B 45 0C 50 8B 45 08 50 FF 15 ?? ?? ?? ?? 59 59 5D C2 08 00 }
	$_5d57c0183ab9f82fac59c1fa69166da6 = { 53 56 57 8B FA 8B F0 8B C6 E8 ?? ?? ?? ?? 8B D8 8B C7 8B D3 E8 ?? ?? ?? ?? 8B D6 8B 37 85 DB 74 21 66 8B 02 66 83 F8 ?? 72 0A 66 83 F8 ?? 77 04 66 83 ?? ?? 66 89 06 83 C2 02 83 C6 02 4B 85 DB 75 DF 5F 5E 5B C3 }
 condition:
     any of them // out of 8

}
