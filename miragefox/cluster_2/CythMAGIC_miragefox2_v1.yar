rule CythMAGIC_miragefox2_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "bf5d58ca10daf579d57467071a8f52fa6b93a7a1"
	size_of_cluster = "3"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_5fc84f1120227c8d342631bce1ce4ba3 = { 55 8B EC 53 8B 5D 14 56 57 3B 5D 24 74 1F 8D 4D 1C E8 91 00 00 00 8B 70 08 8D 4D 2C E8 86 00 00 00 8B 78 08 B9 02 22 00 00 F3 A5 EB DC 8B 45 08 8D 75 2C 8B F8 A5 A5 A5 A5 5F 5E 5B 5D C3 }
	$_a46f5ac688783ea0df12b578885e08c1 = { 55 8B EC 51 53 8B 5D 08 8B C3 56 C1 E0 02 85 C0 57 8B F1 7D 02 33 C0 50 E8 ?? ?? ?? ?? 8B F8 8B C3 C1 E8 02 59 8B 4E 10 8D 04 87 89 45 FC 8B D0 8B 46 20 83 C0 04 3B C8 74 11 8B 19 83 C1 04 89 1A 83 C2 04 3B C8 75 F2 8B 5D 08 FF 76 24 E8 ?? ?? ?? ?? 8B 45 FC 59 89 7E 24 89 5E 28 5F 5E 5B C9 C2 04 00 }
	$_524ebd17f0e4268f17dddcd32f773437 = { 55 8B EC 53 8B 5D 24 56 57 39 5D 14 74 1F 8B 75 14 8B 7D 34 B9 02 22 00 00 F3 A5 8D 4D 2C E8 1B 00 00 00 8D 4D 0C E8 13 00 00 00 EB DC 8B 45 08 8D 75 2C 8B F8 A5 A5 A5 A5 5F 5E 5B 5D C3 }
	$_4255e7ef7d2a8ffe65b69422307e5441 = { 55 8B EC 51 33 C0 39 45 0C 77 02 C9 C3 56 8B 35 14 10 01 00 8D 4D FC 57 51 50 89 45 FC FF D6 FF 75 FC E8 ?? ?? ?? ?? 8B F8 59 8D 45 FC 50 57 FF D6 FF 75 0C 8B F0 57 FF 75 08 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5F 5E C9 C3 }
 condition:
       all of them // out of 4

}
