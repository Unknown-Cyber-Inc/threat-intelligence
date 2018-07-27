rule CythMAGIC_crysis_v2
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "f6d1302586c2ef0cc8b81f98402c1ba56c9bc05d"
	size_of_cluster = "6"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_f78f1b4578257742b3b1c7c5bff089e1 = { 55 8B EC 51 8B 45 08 89 45 FC 8B 4D 0C 8B 55 0C 83 EA 01 89 55 0C 85 C9 74 21 8B 45 FC 50 E8 7D F7 FF FF 8B 4D FC 8D 54 01 01 89 55 FC 8B 45 FC 0F BE 08 85 C9 75 02 EB 02 EB CF 8B 55 FC 0F BE 02 85 C0 75 04 33 C0 EB 03 8B 45 FC 8B E5 5D C3 }
	$_92357e7a036e7f0d2626e612eceacbdc = { 55 8B EC 8B 45 08 8B 48 08 51 E8 01 01 00 00 83 C4 04 8B 55 08 8B 42 08 50 8B 4D 08 51 E8 0E 01 00 00 83 C4 08 8B 55 08 83 7A 1C 00 74 05 E8 ?? ?? ?? ?? 8B 45 08 50 E8 14 00 00 00 83 C4 04 8B 4D 08 51 E8 ?? ?? ?? ?? 83 C4 04 5D C3 }
	$_8b20c92b0048e977b1f450232d806996 = { 55 8B EC 8B 45 08 0F BF 48 04 8B 55 08 8B 42 0C 0F B7 4C 48 FE 85 C9 75 20 8B 55 08 0F BF 42 04 83 F8 01 7E 14 8B 4D 08 66 8B 51 04 66 83 EA 01 8B 45 08 66 89 50 04 EB CA 8B 45 08 5D C3 }
	$_9d726460ff271cf160d49e9349eef15a = { 55 8B EC 8B 45 0C 8B 4D 08 8B 54 81 0C 52 E8 DD F4 FF FF 83 C4 04 8B 45 0C 8B 4D 08 8B 54 81 0C 52 8B 45 08 50 E8 E6 F4 FF FF 83 C4 08 8B 4D 0C 8B 55 08 8B 44 8A 10 50 E8 B3 F4 FF FF 83 C4 04 8B 4D 0C 8B 55 08 8B 44 8A 10 50 8B 4D 08 51 E8 BC F4 FF FF 83 C4 08 5D C3 }
	$_d74e6e7b11bed40ae471f20551c54344 = { 55 8B EC 83 EC 08 C7 45 FC 00 00 00 00 C7 45 F8 00 00 00 00 8B 45 08 50 6A 00 6A 01 E8 1F EA FF FF 89 45 F8 83 7D F8 00 74 18 6A 00 8B 4D F8 51 E8 1B EA FF FF 89 45 FC 8B 55 F8 52 FF 15 20 B0 40 00 8B 45 FC 8B E5 5D C3 }
 condition:

   any of them // out of 5

}
