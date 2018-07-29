rule CythMAGIC_miragefox5_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "4b0f99c22c7ac12700ff4f9b18f1c8c34e76c4e9"
	size_of_cluster = "1"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_cb12bdaefd0afb9ef78007df6fa8b5fb = { B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 8D 4D EC E8 ?? ?? ?? ?? 8B 4E 04 83 65 FC 00 8D 45 EC 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 85 F6 75 0D FF 75 08 8D 4D EC E8 ?? ?? ?? ?? 8B F0 83 4D FC FF 8D 4D EC E8 ?? ?? ?? ?? 8B 4D F4 8B C6 5E 64 89 0D 00 00 00 00 C9 C2 08 00 }
	$_5cb62f438ea938679953cc3d4e7bde43 = { 53 56 57 6A 00 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 7C 24 18 59 59 8B F7 6A 1F 5B E8 ?? ?? ?? ?? 6A 1A 99 59 F7 F9 83 C2 61 66 89 16 46 46 4B 75 EA 66 83 67 3E 00 5F 5E 5B C2 04 00 }
	$_1d631025f15316635d829f0dbef14e16 = { 56 FF 74 24 08 E8 ?? ?? ?? ?? 59 BE ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F0 83 C4 18 85 F6 74 19 56 FF 74 24 14 6A 02 FF 74 24 18 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 14 5E C3 }
	$_2b20bd3b872069cb2e51e860f635c086 = { B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 08 56 8B F1 83 66 04 00 89 06 85 C0 74 06 8B 08 50 FF 51 04 6A 08 E8 ?? ?? ?? ?? 59 8B C8 89 4D 08 83 65 FC 00 85 C9 74 07 E8 ?? ?? ?? ?? EB 02 33 C0 8B 4D F4 89 46 04 8B C6 5E 64 89 0D 00 00 00 00 C9 C2 04 00 }
	$_43190aee54ec2965895f12975c3ea81e = { 55 8B EC 51 8B 01 8D 55 FC 56 52 8B 08 68 ?? ?? ?? ?? 50 FF 11 8B F0 85 F6 75 17 8B 45 FC 50 8B 08 FF 91 14 01 00 00 8B F0 8B 45 FC 50 8B 08 FF 51 08 8B C6 5E C9 C3 }
 condition:
        all of them // out of 5
}
