rule CythMAGIC_petya1_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "f152b026176d4eb1819cd55e7ace77c9cb3c3796"
	size_of_cluster = "2"
	criteria = "clones with 5 <= block_counts <=50, 10 <= instr_counts <=100, 50 <= byte_counts <= 100, 0.8 <= coverage <= 1"
 strings:

	$_83c2096186245cc009a2d96d88ccd1e0 = { 55 8B EC 51 83 65 FC 00 56 8D 45 FC 50 6A 00 8B F1 E8 C9 01 00 00 85 C0 74 19 8B 4D FC 8B 11 8B 75 08 0F B7 0A 66 89 0E 83 C2 02 83 C6 02 66 85 C9 75 EF 5E C9 C2 04 00 }
	$_8e7dfe511c41d4b9187740090b87d88f = { 55 8B EC 53 8B 5D 08 85 DB 74 2D 8B 03 56 8B 35 ?? ?? ?? ?? 57 8B 3D ?? ?? ?? ?? 85 C0 74 08 50 6A 00 FF D7 50 FF D6 8B 5B 04 85 DB 74 08 53 6A 00 FF D7 50 FF D6 5F 5E 5B 5D C2 04 00 }
	$_b32c182cbd4bb2dd3111220261bc49b1 = { 55 8B EC 83 EC 0C 53 56 8B 35 ?? ?? ?? ?? 57 33 DB 53 53 6A FF FF 75 08 BF E9 FD 00 00 53 57 FF D6 89 45 FC 3B C3 74 2C 03 C0 50 53 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 45 F8 3B C3 74 14 FF 75 FC 50 6A FF FF 75 08 53 57 FF D6 85 C0 8B 45 F8 75 02 8B C3 5F 5E 5B C9 C2 04 00 }
	$_abe0e6de2a0ef73085b3337aa1549824 = { 55 8B EC 83 EC 0C 53 56 8D 70 14 56 33 DB 43 53 68 0E 66 00 00 FF 70 08 FF 15 54 D0 00 00 89 45 F4 85 C0 74 26 57 8B 3D 60 D0 00 00 6A 00 8D 45 FC 50 6A 04 FF 36 89 5D FC FF D7 6A 00 8D 45 F8 50 6A 03 FF 36 89 5D F8 FF D7 5F 8B 45 F4 5E 5B C9 C3 }
	$_f29d42b32ec1bb4da45bfc755bd5fb9d = { 55 8B EC 83 EC 24 85 C0 74 2C 66 83 38 00 74 26 8D 55 DC 89 75 FC 2B D0 0F B7 08 66 89 0C 02 83 C0 02 66 85 C9 75 F1 56 8D 45 DC 50 FF 75 08 E8 9D 02 00 00 EB 02 33 C0 C9 C2 04 00 }
	$_31388114be59de32ef74324adb410377 = { 55 8B EC 51 56 57 8B F0 33 FF 85 F6 74 35 56 FF 15 ?? ?? ?? ?? 33 C0 89 45 FC 3B D8 74 02 8B 03 8D 4D FC 51 FF 75 08 E8 5D FF FF FF 8B F8 85 FF 74 0A 8B 45 FC C7 40 04 01 00 00 00 56 FF 15 ?? ?? ?? ?? 8B C7 5F 5E C9 C2 04 00 }
	$_899591d642bce48eb541fe75b4d1bf86 = { 55 8B EC 51 56 8D 45 FC 50 33 F6 21 75 FC 6A 65 56 FF 15 ?? ?? ?? ?? 8B 4D FC 85 C0 75 11 8B 41 10 A9 00 80 00 00 75 04 A8 18 74 03 33 F6 46 85 C9 74 07 51 FF 15 ?? ?? ?? ?? 8B C6 5E C9 C3 }
	$_8f64f8765a2c6213bb1e32df15d811b8 = { 55 8B EC 53 57 8B 3D ?? ?? ?? ?? 6A 08 6A 08 FF D7 50 FF 15 ?? ?? ?? ?? 8B D8 85 DB 74 22 8B 45 08 FF 75 0C 83 23 00 89 43 04 E8 19 00 00 00 85 C0 75 0D 53 33 DB 53 FF D7 50 FF 15 ?? ?? ?? ?? 5F 8B C3 5B 5D C2 08 00 }
	$_eb7017440e092cf3ccd5f8d5e8599770 = { 55 8B EC 51 56 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 50 C7 45 FC 00 00 00 00 FF 15 20 20 00 10 8B F0 83 FE FF 75 07 33 C0 5E 8B E5 5D C3 8B 55 0C 8B 45 08 57 6A 00 8D 4D FC 51 52 50 56 FF 15 18 20 00 10 56 8B F8 FF 15 28 20 00 10 8B C7 5F 5E 8B E5 5D C3 }
	$_c66b56cd344d732898005262c8ae80fa = { 55 8B EC B8 00 40 00 00 E8 ?? ?? ?? ?? 33 C0 56 66 89 85 00 C0 FF FF 8D 85 00 C0 FF FF 50 33 F6 E8 ?? ?? ?? ?? 85 C0 74 12 50 8D 85 00 C0 FF FF 50 FF 75 08 E8 CB F8 FF FF 8B F0 8B C6 5E C9 C2 04 00 }
	$_1c8ab53dd7c8a55c31f9d499020cbee6 = { 55 8B EC 53 56 8B 75 0C 57 FF 36 8B 7D 08 FF 37 33 DB FF 15 ?? ?? ?? ?? 85 C0 75 11 FF 76 04 FF 77 04 FF 15 ?? ?? ?? ?? 85 C0 75 01 43 5F 5E 8B C3 5B 5D C2 0C 00 }
	$_4f3f0a6ff499d4cc119273d9ce505020 = { 55 8B EC 0F B7 51 14 8D 54 0A 18 0F B7 49 06 57 33 C0 33 FF 85 C9 7E 28 53 56 8B 72 0C 3B 75 08 77 0A 8B 5A 10 03 DE 3B 5D 08 73 0A 83 C2 28 47 3B F9 7C E6 EB 08 8B 42 14 2B C6 03 45 08 5E 5B 5F 5D C2 04 00 }
	$_affae3dcc23f69e6cf47d48632d4fd91 = { 55 8B EC 56 33 F6 33 C0 39 75 10 57 0F 95 C0 56 56 40 50 56 56 68 00 00 00 40 FF 75 08 FF 15 84 D1 00 00 8B F8 83 FF FF 74 21 56 8D 45 10 50 53 FF 75 0C 57 FF 15 BC D1 00 00 85 C0 74 06 39 5D 10 75 01 46 57 FF 15 A8 D1 00 00 5F 8B C6 5E 5D C2 0C 00 }
	$_3b44837856115225789849f42144d87d = { 55 8B EC 81 EC 18 06 00 00 56 8D 85 E8 F9 FF FF 50 33 F6 E8 AA FF FF FF 85 C0 74 37 8D 85 E8 F9 FF FF 50 FF 15 28 D2 00 00 56 85 C0 75 2A 68 00 00 00 04 6A 02 56 56 68 00 00 00 40 8D 85 E8 F9 FF FF 50 FF 15 84 D1 00 00 33 C9 83 F8 FF 0F 95 C1 8B F1 8B C6 5E C9 C3 FF 15 D4 D0 00 00 }
	$_852d78e84fc96117a814321d03ac1ac5 = { 55 8B EC 51 83 65 FC 00 8D 45 FC 50 E8 54 02 00 00 85 C0 74 23 8B 45 FC 8B 08 8B 55 08 0F B7 01 66 89 02 83 C1 02 83 C2 02 66 85 C0 75 EF 33 C0 39 45 08 0F 95 C0 EB 02 33 C0 C9 C2 04 00 }
	$_75757c6d76cd10d9494b2fc596d30612 = { 55 8B EC 56 68 48 F1 01 00 33 F6 FF 15 24 D2 00 00 50 68 64 41 01 00 FF 75 08 FF 15 44 D2 00 00 85 C0 74 13 FF 75 08 FF 15 40 D2 00 00 85 C0 74 06 33 C9 66 89 08 46 8B C6 5E 5D C2 04 00 }
	$_d4a6a29e0debafac63cfb74b0fb415f7 = { 55 8B EC 56 57 33 F6 56 6A 02 6A 02 56 56 68 00 00 00 40 FF 75 08 FF 15 ?? ?? ?? ?? 8B F8 83 FF FF 74 24 56 8D 45 08 50 53 FF 75 0C 89 75 08 57 FF 15 ?? ?? ?? ?? 85 C0 74 06 3B 5D 08 75 01 46 57 FF 15 ?? ?? ?? ?? 5F 8B C6 5E 5D C2 08 00 }
	$_a9e40d0af2350113f1667c2c1bf00d59 = { 55 8B EC 57 33 FF 39 7D 08 74 44 68 48 F1 01 00 FF 15 24 D2 00 00 3B C7 74 35 8B C8 56 8D 71 02 66 8B 11 83 C1 02 66 3B D7 75 F5 2B CE D1 F9 5E 81 F9 04 01 00 00 73 17 8B 55 08 2B D0 0F B7 08 66 89 0C 02 83 C0 02 66 3B CF 75 F1 33 FF 47 8B C7 5F 5D C2 04 00 }
	$_67c284016a4f47d831058a661858f2af = { 55 8B EC 56 FF 75 08 33 F6 FF 15 ?? ?? ?? ?? 85 C0 74 2A 8B 40 0C 8B 00 0F B6 48 03 51 0F B6 48 02 51 0F B6 48 01 0F B6 00 51 50 68 ?? ?? ?? ?? FF 75 08 FF 15 ?? ?? ?? ?? 83 C4 18 46 8B C6 5E 5D C2 04 00 }
	$_3328f103ca768cee405628d050e7234d = { 55 8B EC 81 EC 14 01 00 00 57 68 14 01 00 00 33 FF 8D 85 EC FE FF FF 57 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 85 EC FE FF FF 50 C7 85 EC FE FF FF 14 01 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 0A 83 BD F0 FE FF FF 05 76 01 47 8B C7 5F C9 C3 }
 condition:

    7 of them

}
