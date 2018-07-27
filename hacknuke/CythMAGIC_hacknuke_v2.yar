rule CythMAGIC_hacknuke_v2
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "e39a10201dc570ab109e77da36b8526c4c7dd72d"
	size_of_cluster = "1"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_45de19a4d4428c8bb0fa80a338351b3e = {  8B 4D F0 83 C1 5C E9 F7 68 FF FF 6A FF 68 8B C7 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 89 74 24 04 8D 4E 5C E8 52 11 01 00 33 C0 8B CE 89 44 24 10 C7 06 4C D2 41 00 89 46 54 C7 46 58 FF FF FF FF 88 46 60 E8 FB 00 00 00 8B 4C 24 08 8B C6 64 89 0D 00 00 00 00 5E 83 C4 10 C3 }
	$_a56099d94b3e3ed1d1af3d9d44cc5330 = { 56 8B F1 57 8B 46 0C 85 C0 74 37 83 7E 10 00 75 40 BF 00 04 00 00 57 FF 76 08 FF 70 04 FF 15 ?? ?? ?? ?? FF 74 24 0C 8B 4E 0C 66 25 FB F6 FF 76 04 0B C7 50 FF 76 08 FF 71 04 FF 15 ?? ?? ?? ?? EB 0F FF 74 24 0C 8B 46 14 FF 70 ?? E8 ?? ?? ?? ?? 5F 5E C2 04 00 }
	$_3ba5ad8bda40f400f970652f753d9779 = { 8B 44 24 04 56 57 8B F9 85 C0 7E 0B 8D 04 40 8D 34 80 C1 E6 02 EB 03 8B 77 34 8D 44 24 0C 50 E8 ?? ?? ?? ?? 03 C6 83 C4 04 89 47 30 8B 47 44 40 8B CF 89 77 34 89 47 44 E8 ?? ?? ?? ?? 5F 5E C2 04 00 }
	$_c94678bc75ba2b4f441254bae3868026 = { 55 56 8B F1 33 ED 8B 46 54 85 C0 7E 34 57 53 33 FF B3 01 8B 4C BE 04 8D 44 24 14 50 83 C1 08 E8 FC ED FF FF 84 C0 74 0C 8B 4C BE 04 E8 BF FA FF FF 88 5E 60 8B 46 54 45 0F BF FD 3B F8 7C D4 5B 5F 5E 5D C2 04 00 }
	$_c79abc0d1d98bc815e70d82d61b71e4d = {  8B 4D F0 83 C1 04 E9 67 68 FF FF 64 A1 00 00 00 00 6A FF 68 1B C8 41 00 50 64 89 25 00 00 00 00 56 8B F1 8D 4E 08 C7 44 24 0C 00 00 00 00 C7 06 00 00 00 00 E8 04 0C 01 00 8D 4E 04 C7 44 24 0C FF FF FF FF E8 F4 0B 01 00 8B 4C 24 04 5E 64 89 0D 00 00 00 00 83 C4 0C C3 }
	$_84f626e702d1de067676a328516f5e88 = { 53 8B D9 55 56 8D 6B 04 57 8B CD E8 ?? ?? ?? ?? 8D 4B 08 E8 ?? ?? ?? ?? 8B CB E8 41 FF FF FF 8B 44 24 18 3D DC 00 00 00 74 0E 3D 60 01 00 00 75 14 B9 58 00 00 00 EB 05 B9 37 00 00 00 8B 74 24 14 8B FB F3 A5 C7 03 60 01 00 00 A1 ?? ?? ?? ?? 50 8B CD E8 ?? ?? ?? ?? 5F 5E 8B C3 5D 5B C2 08 00 }
	$_a81101cc45b6b5d8ac14645b87251c78 = { 55 56 8B F1 33 ED 8B 46 54 85 C0 7E 38 57 53 8B 5C 24 18 33 FF 8B 4C BE 04 8D 44 24 14 50 83 C1 08 E8 6A EF FF FF 84 C0 74 0E 8B 4C BE 04 53 E8 3C FC FF FF C6 46 60 01 8B 46 54 45 0F BF FD 3B F8 7C D2 5B 5F 5E 5D C2 08 00 }
	$_7f86d890046e62d5e6df1cf4186b93f9 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 53 56 57 89 65 E8 C7 45 FC 00 00 00 00 A1 ?? ?? ?? ?? 85 C0 74 1B C7 45 FC 01 00 00 00 FF D0 B8 01 00 00 00 C3 8B 65 E8 C7 45 FC 00 00 00 00 C7 45 FC FF FF FF FF E8 11 00 00 00 E8 FD FE FF FF }
 condition:

    any of them // out of 8

}
