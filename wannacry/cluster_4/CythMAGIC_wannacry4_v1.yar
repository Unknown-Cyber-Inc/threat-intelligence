rule CythMAGIC_wannacry4_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "f01bbe9609a7490d4a1a53fd4eb4090e4ae1ef2f"
	size_of_cluster = "8"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_c0604207ee6a167e456c295f4be47e95 = { 53 56 8B F1 8B 46 04 B3 01 83 F8 FF 74 20 80 7E 10 00 75 16 83 7E 0C 00 75 10 50 FF 15 ?? ?? ?? ?? 8B D8 4B F7 DB 1A DB FE C3 83 4E 04 FF 83 66 0C 00 84 DB 75 13 38 5E 14 74 0E 83 C6 1E 56 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E 8A C3 5B C3 }
	$_63692c12d27d6af5a4be3fdce329302a = { 53 8B 5C 24 0C 56 8B 74 24 14 57 33 FF 4E 74 29 8B 44 24 10 8B D3 2B D0 0F B7 08 66 85 C9 74 19 66 83 F9 2F 75 05 6A 5C 59 EB 03 0F B7 C9 66 89 0C 02 47 40 40 3B FE 72 DF 33 C0 66 89 04 7B 5F 5E 5B C2 0C 00 }
	$_d0123dc20f14503b0a7d8818aeb83d4b = { 83 3D ?? ?? ?? ?? ?? 56 57 8B F8 8B F1 7C 05 E8 79 EE FF FF 8B CE E8 C2 FF FF FF 33 C0 8B 90 ?? ?? ?? ?? 8B 8E F4 00 00 00 89 14 08 83 C0 04 83 F8 20 7C E9 8B 86 F4 00 00 00 81 30 20 00 08 02 8B 86 F4 00 00 00 8B 4C 24 0C 31 48 08 8B B6 F4 00 00 00 81 CF 00 20 00 00 C1 E7 10 31 7E 0C 5F 5E C2 04 00 }
	$_53624cb50e913b0b1038862d1327986d = { 56 8B 74 24 08 56 E8 ?? ?? ?? ?? 59 8B C8 EB 0E 0F B7 04 4E 50 E8 ?? ?? ?? ?? 84 C0 75 19 49 79 EF 66 83 3E 00 74 0A 66 83 7E 02 3A 8D 46 04 74 02 8B C6 5E C2 04 00 8D 44 4E 02 EB F6 }
	$_2efb98ab27599bf224c3c5b86b53eb22 = { 55 8B EC 8B 45 0C 56 57 8B 7D 14 85 C0 74 1A 66 83 38 00 74 14 8B 75 10 3B F0 74 27 57 50 56 E8 ?? ?? ?? ?? 83 C4 0C EB 1A 83 7D 08 00 8B 75 10 74 0C 57 56 FF 75 08 E8 ?? ?? ?? ?? EB 05 33 C0 66 89 06 85 FF ?? ?? 33 C0 66 89 44 7E FE 5F 8B C6 5E 5D C2 10 00 }
	$_e086e86111780171a7f58a0bb825696a = { 55 8B EC B8 00 10 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 3D 00 06 00 00 72 35 68 00 08 00 00 8D 85 00 F0 FF FF 50 6A FF FF 75 08 6A 20 FF 15 ?? ?? ?? ?? 85 C0 74 18 FF 75 0C 33 C0 66 89 45 FE 8D 85 00 F0 FF FF 50 FF 75 08 E8 ?? ?? ?? ?? C9 C2 08 00 }
	$_080ba9a0fdb312149d5a42e9bb28a550 = { 53 8B 5C 24 0C 56 8B 74 24 14 57 33 FF 4E 74 1F 8B 44 24 10 8B D3 2B D0 8A 08 84 C9 74 11 80 F9 2F 75 03 80 C1 2D 47 88 0C 02 40 3B FE 72 E9 C6 04 1F 00 5F 5E 5B C2 0C 00 }
	$_1fc59fd6762bc7af5e28b5e5fc1c5d96 = { 56 8B F1 8B 46 08 80 B8 ?? ?? ?? ?? ?? 75 28 05 ?? ?? ?? ?? 50 FF 74 24 10 6A 01 E8 ?? ?? ?? ?? 84 C0 74 19 8B 76 08 80 BE ?? ?? ?? ?? ?? 74 0D C6 86 ?? ?? ?? ?? ?? B0 01 5E C2 08 00 6A 02 E8 ?? ?? ?? ?? FF 74 24 0C 6A 06 E8 ?? ?? ?? ?? 32 C0 EB E6 }
	$_5b4395c06bf094b724a803fe6b3b4075 = { 94 EE AD 82 A9 19 AB 11 1F 85 1E F7 1B AF B7 E8 48 01 E6 34 71 09 1B 66 AF E9 B3 1D C9 3A 6F DB EB A5 42 76 B1 58 7A F6 D7 6A 12 F2 B8 E6 9B 8D 43 D8 60 DD 00 9B C9 BE EF AE 5B 10 BE 3F 73 6B BB 2F D3 8E EA 2B F3 1E C8 53 E5 C9 17 65 4C 1A F3 68 82 B6 C6 54 2F C3 }
	$_310ee44feac6e9253db4885f9f6e8249 = { 55 8B EC B8 00 10 00 00 E8 ?? ?? ?? ?? 53 56 FF 75 08 8B 35 ?? ?? ?? ?? FF D6 85 C0 0F 95 C3 84 DB 75 26 68 00 08 00 00 8D 85 00 F0 FF FF 50 FF 75 08 E8 ?? ?? ?? ?? 84 C0 74 0E 8D 85 00 F0 FF FF 50 FF D6 85 C0 0F 95 C3 5E 8A C3 5B C9 C2 04 00 }
	$_63e56c8d105e15ec145c5394de5eb008 = { 55 8B EC B8 00 10 00 00 E8 ?? ?? ?? ?? 56 8B 35 ?? ?? ?? ?? 57 FF 75 08 FF D6 8B F8 83 FF FF 75 23 68 00 08 00 00 8D 85 00 F0 FF FF 50 FF 75 08 E8 ?? ?? ?? ?? 84 C0 74 0B 8D 85 00 F0 FF FF 50 FF D6 8B F8 8B C7 5F 5E C9 C2 04 00 }
	$_0bea05e5fe37e01de9794cc65dc865f6 = { 43 17 0A 2A 9C  D8 AF A4 15 81 16 68 F8 97 D5 06 B8 B5 46 7C F3 62 B7 F6 3B 68 A5 8B EB 7B 47 83 37 D9 77 82 22 6A 42 39 DE 87 48 F4  C9 66 25 38 6B 61 BD 1C A5 EF 84 86 30 D6 DC AF D5 7F 46 05 F8 91 9A 80 C1 9E 29 E9 EA F8  }
	$_0aad9d092642760f18d639af853b0d84 = { 55 8B EC 56 FF 75 10 8B 75 0C 56 56 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 84 C0 74 42 53 6A 01 FF 75 08 E8 ?? ?? ?? ?? 6A 00 56 FF 75 08 FF 15 ?? ?? ?? ?? 85 C0 0F 95 C3 84 DB 75 1F FF 75 08 6A 15 E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 6A 09 8B CE E8 ?? ?? ?? ?? 8A C3 5B 5E 5D C2 0C 00 }
	$_1dce3de5c56f65985116e0235f19ed82 = { 56 8B F1 8B 86 ?? ?? ?? ?? 80 B8 ?? ?? ?? ?? ?? 75 4E 05 ?? ?? ?? ?? 50 8D 46 1E 50 6A 02 E8 ?? ?? ?? ?? 84 C0 74 0F 8B 86 ?? ?? ?? ?? 80 B8 ?? ?? ?? ?? ?? 75 1D 8B CE E8 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 68 FF 00 00 00 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? C6 80 ?? ?? ?? ?? ?? 5E C3 }
	$_e47f0ce90cef882289e8d1d75d2a6bb6 = { 8B 44 24 04 83 B8 ?? ?? ?? ?? ?? 53 75 0C 80 B8 ?? ?? ?? ?? ?? 0F 97 C3 EB 0A 80 B8 ?? ?? ?? ?? ?? 0F 95 C3 80 B8 ?? ?? ?? ?? ?? 75 02 32 DB 84 DB 74 1C 56 FF 74 24 10 8D 70 1E 56 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 6A 22 E8 ?? ?? ?? ?? 5E 33 C0 84 DB 0F 94 C0 5B C2 08 00 }
	$_a271af4c5c461fd0b2567927d11a8957 = { 8B 11 56 85 D2 74 4A 8B 74 24 08 8B 06 85 C0 74 40 83 FA 01 75 04 3B C2 74 09 83 FA 02 75 11 3B C2 75 0D 8B 41 04 2B 46 04 F7 D8 1B C0 40 EB 23 83 FA 03 75 18 3B C2 75 14 6A 20 83 C6 04 83 C1 04 56 51 E8 ?? ?? ?? ?? 83 C4 0C EB DC 32 C0 EB 02 B0 01 5E C2 04 00 }
	$_bf64ded23a3bc12df1846439de5b02f1 = { 55 8B EC 8B 01 81 EC 54 0B 00 00 56 8B 75 08 89 06 83 39 01 75 06 8B 41 04 89 46 04 83 39 02 75 08 8B 41 04 F7 D0 89 46 04 83 39 03 75 1F 83 C1 08 51 8D 8D AC F4 FF FF E8 35 FF FF FF 83 C6 04 56 8D 85 AC F4 FF FF 50 E8 ?? ?? ?? ?? 5E C9 C2 04 00 }
	$_da0fa2bca3f53bc10c8e6b5088af9306 = { 53 56 8B F1 57 8B BE ?? ?? ?? ?? 03 BE ?? ?? ?? ?? 33 DB 83 BE ?? ?? ?? ?? ?? 75 08 8B 86 ?? ?? ?? ?? EB 11 FF B6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 03 86 ?? ?? ?? ?? 03 F8 8B C7 5F 13 DB 5E 8B D3 5B C3 }
	$_5cb154c23f1c7cd49a833cf111ef1e90 = { 56 8B 74 24 08 66 83 3E 5C 75 07 66 83 7E 02 5C 74 18 56 E8 ?? ?? ?? ?? 84 C0 74 13 0F B7 46 04 50 E8 ?? ?? ?? ?? 84 C0 74 05 33 C0 40 EB 02 33 C0 5E C2 04 00 }
	$_5b8f19af230d52537c476bf190d303eb = { 56 8B 74 24 0C FF 74 24 08 C6 86 44 10 00 00 00 E8 ?? ?? ?? ?? 84 C0 74 04 32 C0 EB 43 56 FF 74 24 0C 6A FF E8 91 FD FF FF 83 F8 FF 74 EB 57 50 FF 15 ?? ?? ?? ?? 83 A6 40 10 00 00 00 8D BE 08 10 00 00 FF 37 E8 ?? ?? ?? ?? FF 37 88 86 0C 10 00 00 E8 ?? ?? ?? ?? 88 86 0D 10 00 00 B0 01 5F 5E C2 0C 00 }
	$_5a1367ce9cd62e756111ac9ea58c1cec = { 56 57 8B F1 EB 2C 8B 86 ?? ?? ?? ?? 83 F8 ?? 74 2C 83 F8 ?? 75 13 FF 74 24 0C 8D 8E ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 75 1B 8B CE E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 8B F8 85 FF 75 C9 33 C0 5F 5E C2 04 00 8B C7 EB F7 }
	$_6d3fef4de8249cc81e0600092ccba67d = { 8B 44 24 04 56 8B F1 89 06 83 F8 01 75 04 83 66 04 00 83 F8 02 75 04 83 4E 04 FF 83 F8 03 75 09 8D 46 ?? 50 E8 ?? ?? ?? ?? 8B 44 24 0C 83 F8 08 72 03 6A 08 58 89 86 ?? ?? ?? ?? 5E C2 08 00 }
	$_c34635ab659a67f0e6abb810c2302ea9 = { 55 8B EC B8 00 10 00 00 E8 ?? ?? ?? ?? 53 56 FF 75 0C 8B 35 ?? ?? ?? ?? FF 75 08 FF D6 85 C0 0F 95 C3 84 DB 75 29 68 00 08 00 00 8D 85 00 F0 FF FF 50 FF 75 08 E8 ?? ?? ?? ?? 84 C0 74 11 FF 75 0C 8D 85 00 F0 FF FF 50 FF D6 85 C0 0F 95 C3 5E 8A C3 5B C9 C2 08 00 }
	$_8135d17dd8f16b353cfcbc1c42686ad6 = { 33 C0 83 7C 24 08 01 72 4A 8B 4C 24 04 80 39 52 75 41 83 7C 24 08 07 72 3A 80 79 01 61 75 34 80 79 02 ?? 75 2E 80 79 03 21 75 28 80 79 04 1A 75 22 80 79 05 07 75 1C 8A 49 06 84 C9 75 04 6A 02 EB 10 80 F9 01 75 04 6A 03 EB 07 80 F9 02 75 03 6A 04 58 C2 08 00 }
	$_1a2bb3020755e898d265371fd2629958 = { 8B 44 24 0C 85 C0 74 3A 56 57 8B 7C 24 0C 57 8D 70 FF E8 ?? ?? ?? ?? 2B C7 D1 F8 3B F0 72 0C 57 E8 ?? ?? ?? ?? 8B F0 2B F7 D1 FE 56 57 8B 7C 24 18 57 E8 ?? ?? ?? ?? 83 C4 0C 33 C0 66 89 04 77 5F 5E C2 0C 00 }
	$_e78552ed3e5000e977fcf9c014b48009 = { 56 57 6A 3B FF 74 24 10 33 FF E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 74 17 8D 46 02 50 E8 ?? ?? ?? ?? 80 7C 24 10 00 8B F8 74 05 33 C0 66 89 06 8B C7 5F 5E C2 08 00 }
	$_4bfb6a8341b8c3a5ccde7e4efb37a7d0 = { 55 8B EC 56 6A 05 FF 75 10 8B F1 FF 75 08 8D 86 30 93 00 00 FF 75 0C 50 E8 ?? ?? ?? ?? 84 C0 74 04 B0 01 EB 30 80 7D 14 00 74 28 83 BE A0 93 00 00 00 74 1F 6A 05 FF 75 10 81 C6 8C 93 00 00 FF 75 08 FF 75 0C 56 E8 ?? ?? ?? ?? F6 D8 1A C0 FE C0 EB 02 32 C0 5E 5D C2 10 00 }
	$_1f4a81ce1a1b7c6a03bbc24b831e6c3c = { 55 8B EC 80 B9 ?? ?? ?? ?? ?? 74 1F 8B 45 08 F7 D0 40 83 E0 0F 01 45 08 83 B9 ?? ?? ?? ?? ?? 75 06 83 45 08 10 EB 04 83 45 08 08 8B 45 08 5D C2 04 00 }
	$_388b787defde5684fa923276df20a2bf = { 51 53 55 8B D9 8B 6B 08 8B 43 04 57 BF 00 02 00 00 89 44 24 0C 3B EF 72 34 56 EB 04 8B 44 24 10 83 3D ?? ?? ?? ?? ?? 7C 0F 81 FD 00 04 00 00 72 07 0F 18 88 00 02 00 00 8B 33 6A 40 50 E8 ?? ?? ?? ?? 01 7C 24 10 2B EF 3B EF 73 D0 5E 5F 5D 5B 59 C3 }
	$_4e7157150f5462249fe0c6a58d70bf28 = { 56 8B F1 E8 ?? ?? ?? ?? 8B 8E ?? ?? ?? ?? 3B C8 75 1E 8B 8E ?? ?? ?? ?? 3B CA 75 14 8B 8E ?? ?? ?? ?? 3B C8 75 0A 8B 86 ?? ?? ?? ?? 3B C2 74 17 83 C6 1E 56 6A 37 E8 ?? ?? ?? ?? 6A 01 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E C3 }
	$_8ef2f457b43719ebbcab9354c56fb613 = { 8B 54 24 04 33 C0 39 42 04 75 26 56 6A 08 8B C8 5E F6 C1 01 74 0A D1 E9 81 F1 ?? ?? ?? ?? EB 02 D1 E9 4E 75 EC 89 0C 82 40 3D 00 01 00 00 72 DC 5E C2 04 00 }
 condition:

       3 of them // out of 31
}