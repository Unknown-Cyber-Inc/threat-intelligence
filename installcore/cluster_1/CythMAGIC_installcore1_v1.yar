rule CythMAGIC_installcore1_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "b757e3afade9cf55d0185d82fecf0b9898cd61db"
	size_of_cluster = "14"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_0cde01773de52296714c670e45ef228b = { 53 56 57 55 51 89 04 24 8B 04 24 33 ED 8B FA 85 FF 8B 58 08 8B 04 24 8B 70 0C ?? ?? D1 EB 03 ED 3B DE 77 05 2B F3 83 CD 01 81 FB 00 00 00 01 73 16 C1 E3 08 8B 04 24 E8 44 FF FF FF 33 D2 C1 E6 08 8A D0 0B D6 8B F2 4F 85 FF ?? ?? 8B 0C 24 89 59 08 8B 04 24 89 70 0C 8B C5 5A 5D 5F 5E 5B C3 }
	$_e087de942eb3f651ec0f7e1507c90798 = { 53 56 57 55 8B EA 8B F0 B2 01 8B C6 E8 ?? ?? ?? ?? 8B F8 8B C6 E8 ?? ?? ?? ?? 8B D8 EB 01 4B 3B FB 7D 14 8D 04 1E 50 56 E8 ?? ?? ?? ?? 8A 00 2C 2F 74 EB 2C 2D 74 E7 8B C6 E8 ?? ?? ?? ?? 3B D8 75 0B 8B C5 8B D6 E8 ?? ?? ?? ?? EB 0F 55 8B CB BA 01 00 00 00 8B C6 E8 ?? ?? ?? ?? 5D 5F 5E 5B C3 }
	$_084b80c7f41266965a0ced1c88077e6d = { 68 FE E8 11 0C 53 83 C4 0C 59 31 CE 5B 31 DE 31 FE 5A 31 D6 FF 16 BF E0 DA E5 11 81 F7 E0 52 03 61 E8 C0 15 00 00 31 DA 31 C9 01 D1 83 C4 FC 89 0C 24 FF 10 E8 3A 00 00 00 59 BB 24 41 02 50 B9 90 14 0C 03 31 CB E9 A7 12 00 00  }
	$_ed0ddd82f184adb983d2f293c90d065d = { 56 51 88 0C 24 83 FA 05 7C 36 83 EA 04 8B F0 33 C0 3B D0 7E 2B 8A 0C 06 80 F9 E8 74 05 80 F9 E9 75 19 83 C0 05 80 3C 24 00 74 08 8D 4C 06 FC 01 01 EB 09 8D 4C 06 FC 29 01 EB 01 40 3B D0 7F D5 5A 5E C3 }
	$_615e2e16172b9d1835bd0c887da14274 = { 55 8B EC 51 53 89 4D FC 8B D8 83 FA 50 74 07 B8 01 00 00 00 EB 32 8B 4D 10 8B 55 FC 8B C3 E8 C1 F8 FF FF 85 C0 75 21 8B 0B BA 00 03 00 00 03 4B 04 D3 E2 8B 4D 0C 81 C2 36 07 00 00 03 D2 89 11 8B 55 08 8B 4B 0C 89 0A 5B 59 5D C2 0C 00 }
	$_c4072e966b02efc0eb883c9522494c5b = { 1E 70 23 26 23 23 98 94 E8 EB F4 F4 57 98 94 89 EB F4 98 94 E8 EB F4 F4 57 75 23 F4 A8 D4 47 2D A1 47 03 23 75 1E 70 23 03 23 23 98 94 E8 EB F4 F4 55 F4 98 4E 89 10 E9 FF EB F4 F4 }
	$_46f6e182adbe9d893f38281c3b7e859a = { 53 56 57 81 C4 04 F0 FF FF 50 83 C4 FC 8B FA 8B F0 54 8D 44 24 08 50 68 00 10 00 00 8B C6 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 89 C3 85 DB 7E 17 81 FB 00 10 00 00 7D 0F 8D 54 24 04 8B C7 8B CB E8 ?? ?? ?? ?? EB 09 8B C7 8B D6 E8 ?? ?? ?? ?? 81 C4 04 10 00 00 5F 5E 5B C3 }
	$_dbbc97bca719ea4dd0b4e19ba4e74776 = { 53 8B DA C6 03 00 84 C0 75 04 B0 01 5B C3 80 3D ?? ?? ?? ?? ?? 74 19 8D 43 04 50 FF 15 ?? ?? ?? ?? F7 D8 1B C0 F7 D8 84 C0 74 0E C6 03 01 EB 09 6A 01 E8 ?? ?? ?? ?? 33 C0 5B C3 }
	$_8b6db1224df6881b475f7839c0b742c7 = { 55 8B EC 51 53 56 57 8B F1 89 55 FC 33 D2 89 16 33 C9 EB 1C 80 FA 22 75 05 80 F1 01 EB 11 83 7D FC 00 74 09 8B 1E 8B 7D FC 03 FB 88 17 FF 06 40 8A 10 84 D2 74 0A 80 FA 20 0F 97 C3 0A D9 75 D4 5F 5E 5B 59 5D C3 }
	$_82211b509c8241b03242865dd5d16943 = { 55 8B EC 6A 00 53 56 57 8B D8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? ?? ?? ?? 8D 55 FC E8 4F FF FF FF 8B D0 8B C3 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 FC E8 ?? ?? ?? ?? C3 5F 5E 5B 59 5D C3 }
	$_75d4ee33dcb117cba86598f5fd81b2ac = { 81 F7 83 4A 52 5D 31 CF 31 DB 01 FB 89 D8 83 C4 FC 89 04 24 5E 31 DB E8 87 0E 00 00  B9 BD 49 40 00 31 FF 01 CF 83 C4 FC 89 3C 24 BF ED 6A A4 73 81 F7 5A C9 A2 6B B8 34 E9 54 45 31 C7 E9 F7 FB FF FF 52 57 83 C4 0C 81 E1 2B 8B BF FE 09 D9 83 C4 FC 31 F6 01 E6 31 DB 01 F3 89 0B FF D0 E9 15 F3 FF FF }
	$_f8c4565dab3035271e21f557a2699dae = { 55 8B EC 53 56 84 D2 74 08 83 C4 F0 E8 ?? ?? ?? ?? 8B DA 8B F0 33 D2 8B C6 E8 ?? ?? ?? ?? 8B 45 08 89 46 04 8B 45 0C 89 46 08 84 DB 74 0A 64 8F 05 00 00 00 00 83 C4 0C 8B C6 5E 5B 5D C2 08 00 }
	$_6248c85791a836c6f66a0db71438a189 = {  58 E9 9D 12 00 00 89 E3 89 D8 89 38 BB 6A EE E4 4C B8 4A 90 75 26 31 D8 BB 6E 5A B8 73 31 D8 81 F0 4E 24 29 19 31 F8 E9 E4 F4 FF FF 83 C4 04 01 D6 B8 00 00 00 00 31 F0 89 C3 83 C4 FC 89 1C 24 5F 09 D7 0F 84 70 F6 FF FF 5F 83 C4 FC E9 DF FE FF FF  }
	$_6426ff1d87f3e46ba70ac8926a94fa3b = { 53 6A 0A 68 67 2B 00 00 6A 00 E8 ?? ?? ?? ?? 8B D8 85 DB 75 05 E8 ?? ?? ?? ?? 53 6A 00 E8 ?? ?? ?? ?? 83 F8 2C 74 05 E8 ?? ?? ?? ?? 53 6A 00 E8 ?? ?? ?? ?? 8B D8 85 DB 75 05 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B D8 85 DB 75 05 E8 ?? ?? ?? ?? 8B C3 5B C3 }
	$_1ce80d9059ef11f9717a28b2175e8246 = { 53 56 57 8B F1 8B FA 8B D8 83 3D ?? ?? ?? ?? ?? 75 11 E8 ?? ?? ?? ?? 6A 01 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C7 85 F6 74 25 8B D3 66 81 E2 FF 00 33 C9 8A 08 66 33 D1 0F B7 D2 8B 14 95 ?? ?? ?? ?? C1 EB 08 33 D3 8B DA 4E 40 85 F6 75 DB 8B C3 5F 5E 5B C3 }
	$_c88b77ee588229aa0262737c6c352135 = { 53 56 8B D8 85 DB 7C 3E 3B 1D ?? ?? ?? ?? 7D 36 3B 1D ?? ?? ?? ?? 74 2E 8B F3 C1 E6 03 A1 ?? ?? ?? ?? 8B 44 F0 18 E8 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 8D 44 F0 18 E8 ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? 5E 5B C3 }
	$_8e2637680cc002c9289648b6a88fcaf3 = { 65 66 31 A8 D4 53 D2 AD 53 8B 45 6F 67 4A AD 53 FD 7A 6D 6F 57 AD 53 D8 65 7A 64 67 AD 53 D9 6F 71 23 23 AD 53 BC 54 6F 73 6E AD 53 7B 4A 7A 6D 6F 31 A8 D4 53 85 AD 53 9E 47 6D 65 61 AD 53 E7 6F 5A 73 64 AD 53 C2 6E 6D F4 F4   }
	$_5ff7829244bd48e08aed15d0f295deaa = { 55 8B EC 6A 00 53 56 57 8B D8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 BA ?? ?? ?? ?? 8D 45 FC E8 ?? ?? ?? ?? 8D 45 FC 8B D3 E8 ?? ?? ?? ?? 8B 4D FC B2 01 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 FC E8 ?? ?? ?? ?? C3 5F 5E 5B 59 5D C3 }
 condition:
     3 of them // out of 18
 }
