rule CythMAGIC_miragefox6_v2
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "a24f0069e32cca60ebcd81afd2cc7add6a74dc61"
	size_of_cluster = "1"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_3b81a16a03de3d54b84b781c9880c13e = { 55 8B EC 83 EC 0C 8D 45 F8 56 50 6A 03 6A 00 68 50 94 40 00 68 01 00 00 80 FF 15 10 70 40 00 85 C0 75 3E 8D 45 F4 BE 5C 95 40 00 50 8D 45 FC 50 6A 00 6A 00 56 FF 75 F8 FF 15 0C 70 40 00 6A 01 85 C0 59 75 05 39 4D FC 74 17 8D 45 FC 6A 04 50 6A 04 6A 00 56 FF 75 F8 89 4D FC FF 15 14 70 40 00 5E C9 C3 }
	$_43190aee54ec2965895f12975c3ea81e = { 55 8B EC 51 8B 01 8D 55 FC 56 52 8B 08 68 ?? ?? ?? ?? 50 FF 11 8B F0 85 F6 75 17 8B 45 FC 50 8B 08 FF 91 14 01 00 00 8B F0 8B 45 FC 50 8B 08 FF 51 08 8B C6 5E C9 C3 }
	$_5cb62f438ea938679953cc3d4e7bde43 = { 53 56 57 6A 00 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 7C 24 18 59 59 8B F7 6A 1F 5B E8 ?? ?? ?? ?? 6A 1A 99 59 F7 F9 83 C2 61 66 89 16 46 46 4B 75 EA 66 83 67 3E 00 5F 5E 5B C2 04 00 }
	$_f9f78eb80260732a939db77a617dbd10 = { 56 33 F6 E8 50 00 00 00 85 C0 74 04 33 F6 EB 01 46 6A 00 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 59 E8 ?? ?? ?? ?? 6A 0A 99 59 F7 F9 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 C1 83 25 ?? ?? ?? ?? ?? 83 C2 03 03 C2 69 C0 E8 03 00 00 50 FF 15 ?? ?? ?? ?? 83 FE 05 7C AD 5E C3 }
	$_57d3a9a7e0a44eb8d61a962b41bf802a = { 55 8B EC 83 EC 0C 56 8D 45 F8 57 50 33 FF 6A 03 57 68 ?? ?? ?? ?? 68 01 00 00 80 FF 15 10 70 40 00 3B C7 75 38 8D 45 F4 BE ?? ?? ?? ?? 50 8D 45 FC 50 57 57 56 FF 75 F8 FF 15 0C 70 40 00 85 C0 75 05 39 7D FC 74 16 8D 45 FC 6A 04 50 6A 04 57 56 FF 75 F8 89 7D FC FF 15 14 70 40 00 5F 5E C9 C3 }
	$_2daa42d3bcc20a14776da973a06edb32 = { 53 33 DB 38 5C 24 08 74 22 E8 ?? ?? ?? ?? 84 C0 75 12 E8 ?? ?? ?? ?? 85 C0 75 09 E8 ?? ?? ?? ?? 84 C0 74 07 53 FF 15 ?? ?? ?? ?? 39 1D 00 C0 ?? ?? 7E 07 53 FF 15 ?? ?? ?? ?? FF 74 24 0C FF 05 00 C0 ?? ?? E8 ?? ?? ?? ?? 85 C0 59 74 0F 68 B8 0B 00 00 FF 15 ?? ?? ?? ?? 33 C0 5B C3 53 FF 15 ?? ?? ?? ?? }
	$_5ab064ee8877cb5b687518455a47adb7 = { 6A FF FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 2C 56 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? FF D6 FF 35 ?? ?? ?? ?? FF D6 6A 00 FF 15 ?? ?? ?? ?? 5E 33 C0 C2 04 00 }
	$_fa733fcbe3cdbb83aa0cfd815e1e2164 = { B8 0E 65 40 00 E8 43 41 00 00 8B 45 08 56 8B F1 83 66 04 00 89 06 85 C0 74 06 8B 08 50 FF 51 04 6A 08 E8 58 41 00 00 59 8B C8 89 4D 08 83 65 FC 00 85 C9 74 07 E8 01 F1 FF FF EB 02 33 C0 8B 4D F4 89 46 04 8B C6 5E 64 89 0D 00 00 00 00 C9 C2 04 00 FF 75 08 E8 54 FE FF FF 59 C3 }
	$_83bf8fd2c2182bab6de4bb7da7cd31f3 = { 55 8B EC 51 83 65 FC 00 8D 45 FC 56 8B 35 ?? ?? ?? ?? 50 6A 00 6A 26 6A 00 FF D6 85 C0 74 23 57 FF 75 FC E8 ?? ?? ?? ?? 8B F8 59 8D 45 FC 50 57 6A 26 6A 00 FF D6 8B 07 48 F7 D8 1B C0 23 C7 5F EB 02 33 C0 5E C9 C3 }
 condition:

        any of them // out of 9
}
