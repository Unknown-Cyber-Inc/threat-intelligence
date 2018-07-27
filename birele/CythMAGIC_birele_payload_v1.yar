rule CythMAGIC_birele_payload_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "fb4d7893ce0a54b9d4599c5c7c1eb690c17674ec"
	size_of_cluster = "42"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_609ea1bf9e372b6bb476475066f459e2 = { 55 8B EC A1 ?? ?? ?? ?? 53 50 FF 15 ?? ?? ?? ?? 8B 5D 08 85 C0 74 25 8B 48 04 85 C9 74 1E 8B 01 85 C0 74 18 C7 01 00 00 00 00 8A 08 0F B6 D1 3B D3 73 28 50 E8 ?? ?? ?? ?? 83 C4 04 8D 43 01 50 E8 ?? ?? ?? ?? 83 C4 04 81 FB FF 00 00 00 77 09 0F B6 CB 88 0C 18 5B 5D C3 33 C9 88 0C 18 5B 5D C3 }
	$_8218a7ffc6d3db6311fcdbda270b999d = { 83 EC 0C 8B 44 24 10 8B 54 24 1C 8B 4C 24 14 52 89 44 24 04 8B 44 24 1C 50 89 4C 24 10 8D 4C 24 08 68 90 D1 ?? ?? 51 C7 44 24 14 00 00 00 00 E8 1C 01 00 00 83 C4 10 83 F8 FF 74 1F 8B 4C 24 08 85 C9 74 17 3B 4C 24 04 75 0B 8B 14 24 C6 42 FF 00 83 C4 0C C3 8B 0C 24 C6 01 00 83 C4 0C C3 }
	$_9ee175900dd930d7b653de3d24887dc2 = { 8B 4E 04 53 F6 C1 03 74 10 8B 1E 85 DB 74 0A C1 E9 02 E8 90 FC FF FF EB 02 8B 06 89 07 83 3E 00 74 0C F6 46 04 03 6A 00 59 0F 95 C1 EB 06 8B 4E 04 83 E1 03 8B 57 04 33 D1 83 E2 03 31 57 04 8B 56 04 33 57 04 8B C7 83 E2 03 33 56 04 5B 89 57 04 C3 }
	$_1abe25ef487cea581faccce8431cca1d = { 55 8B EC 51 56 8B 75 08 53 89 4D FC 57 8D 49 00 8B 06 A9 00 00 00 80 0F 95 C3 84 DB 74 05 8D 50 01 EB 08 8B D0 81 CA 00 00 00 80 8B 7D FC 8B CA F0 0F B1 0F 3B 06 74 04 89 06 EB D4 5F 84 DB 5B 74 02 89 16 5E 8B E5 5D C2 04 00 }
	$_5e13734210828417e58bf1208ca8937c = { 8B 4C 24 08 56 57 8B 7C 24 0C 8B 37 6A 04 8D 44 24 10 50 6A 01 6A 06 51 C7 44 24 20 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 ?? ?? FF 15 ?? ?? ?? ?? 50 57 E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 14 5F 5E C3 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 08 5F 5E C3 }
	$_2fdb38125ecb819ce507baf6c797fee0 = {  56 8B 74 24 0C 8B 96 B0 03 00 00 8B 02 85 C0 74 0F 8B 4C 24 08 39 08 74 09 8B 40 08 85 C0 75 F5 5E C3 8B 8E B4 03 00 00 57 8B 79 04 57 51 50 52 E8 8B F9 FF FF 8B 86 B0 03 00 00 83 C4 10 83 38 00 5F 74 DC C7 86 AC 03 00 00 00 00 00 00 8B 00 8B 08 5E C7 44 24 08 00 00 00 00 89 4C 24 04 E9 EC F7 FD FF }
	$_03fc79f51eea0ecf598e94cbfed33bd4 = { 33 C0 89 07 8B 8E ?? ?? ?? ?? 8B 49 10 85 C9 74 46 53 57 56 FF D1 8B D8 83 C4 08 85 DB 75 37 83 3F 01 75 32 8B 16 89 82 ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 8B 8E ?? ?? ?? ?? 3B C1 77 02 8B C1 8B 0E 40 89 81 ?? ?? ?? ?? 8B 16 6A 06 52 E8 ?? ?? ?? ?? 83 C4 08 8B C3 5B C3 }
	$_0dc65e8a2efc262c6433e8fb6b43e212 = { 55 8B EC 51 53 FF 75 08 8D 5D FC 8B C6 E8 ?? ?? ?? ?? 8B 45 FC 5B 3B 46 04 74 14 8B ?? ?? 83 C0 ?? E8 ?? ?? ?? ?? 84 C0 75 05 8D 45 FC EB 09 8B 46 04 89 45 08 8D 45 08 8B 00 89 07 8B C7 C9 C2 04 00 }
	$_acf8bc7c0a8f53d9a465d969b83aaf95 = { 83 EC 0C 8B 44 24 10 8B 4C 24 14 8D 54 24 1C 52 89 44 24 04 8B 44 24 1C 50 89 4C 24 10 8D 4C 24 08 68 90 D1 ?? ?? 51 C7 44 24 14 00 00 00 00 E8 BC 00 00 00 83 C4 10 83 F8 FF 74 1F 8B 4C 24 08 85 C9 74 17 3B 4C 24 04 75 0B 8B 14 24 C6 42 FF 00 83 C4 0C C3 8B 0C 24 C6 01 00 83 C4 0C C3 }
	$_40aa1825d0aafec6ef475081a4006ea8 = { 55 8B EC 83 EC 28 A1 D0 73 49 00 33 C5 89 45 FC 8B 4D 08 33 C0 83 79 14 10 89 45 D8 89 45 DC 89 45 E0 89 45 E4 89 45 E8 89 45 EC 89 45 F0 89 45 F4 89 45 F8 72 02 8B 09 8D 55 D8 52 50 51 FF 15 B0 81 47 00 8B 4D FC F7 D8 1B C0 33 CD F7 D8 E8 08 D8 04 00 8B E5 5D C3 }
	$_cff6e45a590cf11a1d279f7927995abc = { 83 3D ?? ?? ?? ?? ?? 75 3C 6A 00 6A 02 6A 17 FF 15 ?? ?? ?? ?? 83 F8 FF 75 16 33 C0 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 0F 9F C0 C3 50 6A 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 08 33 C0 39 05 ?? ?? ?? ?? 0F 9F C0 C3 }
	$_3f7ba792964b4792864974f2f0c0ecdf = { 6A 00 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 E8 ?? ?? ?? ?? 84 C0 75 07 8B 0E E8 ?? ?? ?? ?? 83 4D FC FF 8B 06 8B 08 8B 49 04 8B 44 01 38 85 C0 74 07 8B 10 8B C8 FF 52 08 E8 ?? ?? ?? ?? C2 04 00 }
	$_5036b5fd82e5b63391007c5e697ab993 = { 6A 24 B8 67 5E 47 00 E8 BF A4 06 00 8B F1 81 FE FF FF FF 7F 72 05 BE FE FF FF 7F 8D 46 01 50 E8 27 75 05 00 8B F8 59 85 FF 75 19 68 20 C7 48 00 8D 4D D4 E8 D0 D2 FF FF 21 7D FC 8D 45 D4 50 E8 3D 01 00 00 56 53 57 E8 07 4E 05 00 83 C4 0C C6 04 3E 00 8B C7 E8 BB A4 06 00 C3 }
	$_a98ac88e57231fab999f669ff60a99d1 = { 55 8B EC 8B 55 08 83 EC 18 89 65 08 8B C4 74 12 C7 00 94 89 ?? ?? C7 00 ?? ?? ?? ?? 89 48 04 89 50 08 89 40 10 83 79 ?? ?? 8D 41 ?? 72 02 8B 00 6A 00 50 E8 ?? ?? ?? ?? 83 C4 20 5D C2 04 00 }
	$_26c1513fdeaf54ba35d074271e2386b1 = { 8B 44 24 0C 8B 4C 24 08 8B 54 24 04 6A 00 50 51 52 FF 15 ?? ?? ?? ?? 83 F8 FF 75 16 FF 15 ?? ?? ?? ?? 2D 33 27 00 00 F7 D8 1B C0 83 E0 ?? 83 C0 ?? C3 8B 4C 24 10 89 01 33 C0 C3 }
	$_acf85635051bad8098f4ae4ef5a071d5 = { 55 56 8B F0 8B C3 2B C6 8D 44 40 01 50 FF 15 40 70 ?? ?? 8B E8 83 C4 04 85 ED 74 26 3B F3 73 22 57 8B FD 0F B6 06 50 68 C0 59 ?? ?? 6A 04 57 E8 2C 05 FE FF 46 83 C4 10 83 C7 03 3B F3 72 E4 8B C5 5F 5E 5D C3 }
	$_111de7fb6336b176c5e901973251de97 = { 56 8B 74 24 08 8A 06 57 8B 7C 24 10 84 C0 74 28 8A 0F 84 C9 74 22 8D 50 9F 80 FA 19 77 02 2C 20 8D 51 9F 80 FA 19 77 03 80 E9 20 3A C1 75 09 8A 46 01 46 47 84 C0 75 D8 8A 06 8D 48 9F 80 F9 19 77 02 2C 20 8A C8 8A 07 5F 5E 8D 50 9F 80 FA 19 77 02 2C 20 33 D2 3A C8 0F 94 C2 8B C2 C3 }
	$_625e7d781d96bdc46c8b33037ea5481f = { 55 8B EC 8B 55 08 8B 01 8B 40 0C 83 EC 08 52 8D 55 F8 52 FF D0 8B 50 04 8B 4D 0C 3B 51 04 75 11 8B 00 3B 01 75 0B B8 01 00 00 00 8B E5 5D C2 08 00 33 C0 8B E5 5D C2 08 00 }
	$_ebef3ada592b56f926929640df36965e = { 8B 41 24 83 38 00 74 07 8B 41 34 8B 00 EB 02 33 C0 85 C0 7E 17 8B 41 34 FF 08 8B 49 24 8B 01 56 8D 70 01 89 31 88 10 0F B6 C2 5E C3 8B 01 0F B6 D2 52 FF 50 ?? C3 }
	$_216f0ffc2f3ec5a6abdae9242f9b7856 = { 51 8B 44 24 08 8B 54 24 0C 33 C9 3B 90 ?? ?? ?? ?? 8D 14 24 52 8B 54 24 18 0F 94 C1 52 8B 54 24 18 52 C7 44 24 0C 00 00 00 00 51 50 8B 84 88 ?? ?? ?? ?? FF D0 8B 4C 24 2C 83 C4 14 ?? ?? ?? ?? ?? ?? 8B 04 24 85 C0 74 0F 83 F8 51 75 0F C7 01 00 00 00 00 33 C0 59 C3 B8 37 00 00 00 59 C3 }
	$_8d4efbc4fb1618d9c01827ca7c859ca3 = { 51 0F BE 41 08 48 74 3E 48 74 37 48 74 04 32 C0 59 C3 D9 EE DC 19 DF E0 F6 C4 41 7A 21 DD 05 30 C2 ?? ?? DC 19 DF E0 F6 C4 41 75 12 DD 01 51 51 DD 1C 24 E8 28 FF FF FF 59 59 84 C0 75 15 33 C0 59 C3 B0 01 59 C3 33 C0 39 41 04 7C 09 7F 04 39 01 72 03 33 C0 40 59 C3 }
	$_affa315945ba3c6b2a06e503a36e9705 = { 56 8B 74 24 08 57 33 FF 39 7E 10 7E 21 8D 49 00 8B 06 8B 0C B8 56 51 E8 ?? ?? ?? ?? 8B 16 C7 04 BA 00 00 00 00 47 83 C4 08 3B 7E 10 7C E2 8B 06 50 FF 15 ?? ?? ?? ?? 83 C4 04 5F C7 06 00 00 00 00 C7 46 14 00 00 00 00 C7 46 10 00 00 00 00 5E C3 }
	$_a46dcc666ca939b452369a80bfa1cc94 = { 55 8B EC 53 8B 5D 10 56 8B 75 0C 3B F3 74 25 57 0F BE 06 8B 7D 14 50 FF 55 18 88 07 FF 45 14 46 83 C4 04 3B F3 75 E9 8B 45 08 8B 4D 14 5F 5E 89 08 5B 5D C3 8B 45 08 8B 55 14 5E 89 10 5B 5D C3 }
	$_324d947172ec419623a42867448c2167 = { 8B 44 24 08 8B 54 24 04 83 F8 01 74 18 83 F8 02 75 0F 8B 8A 38 03 00 00 F7 41 40 00 02 00 00 74 04 33 C9 EB 05 B9 01 00 00 00 83 F8 02 75 0F 8B 82 38 03 00 00 F7 40 40 00 02 00 00 75 0E 3B 8A B0 02 00 00 74 06 89 8A B0 02 00 00 C3 }
	$_0b3e552f0137ef48438bd283da5f1437 = { 53 8B D9 C6 06 25 8D 4E 01 F6 C3 20 74 04 C6 01 2B 41 F6 C3 10 74 04 C6 01 23 41 66 C7 01 2E 2A 83 C1 02 84 C0 74 03 88 01 41 BA 00 30 00 00 23 DA 81 FB 00 20 00 00 75 04 B2 66 EB 15 3B DA 75 04 B2 61 EB 0D 81 FB 00 10 00 00 0F 95 C2 8D 54 12 65 88 11 C6 41 01 00 8B C6 5B C3 }
	$_c3043d26741cdf7f1c537aa1f1b7f1ff = { 8B 4F 40 8B 81 94 00 00 00 85 C0 ?? ?? 8B 41 0C 03 C0 03 C0 56 33 F6 89 73 40 85 C0 ?? ?? 8B 8F ?? ?? ?? ?? 39 41 18 76 27 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B F0 83 C4 0C 85 F6 74 0D 6A 00 56 89 3E E8 ?? ?? ?? ?? 83 C4 08 33 C0 3B F3 0F 95 C0 5E C3 }
	$_3fccd9045a5dd0b52c39dfa337dbfd1c = { 33 C0 39 05 ?? ?? ?? ?? 75 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 07 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 14 85 C0 75 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? F7 D8 1B C0 F7 D0 25 ?? ?? ?? ?? C3 }
	$_771b4cc5aa9e8a8ef0e4df9cee0725b7 = { 53 8B 5C 24 10 B8 CD CC CC CC F7 E3 55 8B 6C 24 ?? 56 8B F2 C1 EE 03 33 C9 57 8B 7C 24 ?? 85 F6 74 12 56 ?? ?? E8 D6 FF FF FF 6B F6 F6 83 C4 0C 8B C8 03 DE 3B ?? 7D 06 80 C3 30 88 1C ?? 41 8B C1 3B ?? 7D 04 C6 04 ?? ?? 5F 5E 5D 5B C3 }
	$_b3e047704aae9ee159c665b85a4bd391 = { 56 57 50 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 83 C4 0C 8B F7 85 FF 74 23 80 3F 00 74 1E 8B FF 8A 06 3C 3A 74 14 0F B6 D0 52 E8 ?? ?? ?? ?? 88 06 46 83 C4 04 80 3E 00 75 E6 8B C7 5F 5E C3 }
	$_f90a26e9051579195bdb9fd1687c5f0f = { 55 8B EC 56 8D 71 F8 8D 46 08 8B 48 F8 8B 49 04 C7 44 01 F8 ?? ?? ?? ?? 50 C7 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? F6 45 08 01 59 74 07 56 E8 ?? ?? ?? ?? 59 8B C6 5E 5D C2 04 00 }
	$_1c4a26ee4dd3c13f72aedeee7bf75020 = { 55 8B EC 51 51 8B 11 85 D2 75 0C 8B 49 04 3B 48 04 1B C0 F7 D8 C9 C3 56 8B 71 04 57 8B 78 04 C1 EE 02 C1 EF 02 89 75 F8 89 7D FC 8D 4D FC 3B FE 72 03 8D 4D F8 FF 31 FF 30 52 E8 C8 55 05 00 83 C4 0C 85 C0 79 04 B0 01 EB 0C 7E 04 32 C0 EB 06 3B F7 1B C0 F7 D8 5F 5E C9 C3 }
	$_bde11cbc622c250df80c254fc5f271de = { 55 8B EC 83 7D 14 00 76 1D 8B 4D 0C 85 C9 74 0D 8A 55 10 E8 ?? ?? ?? ?? 83 F8 FF 75 04 C6 45 08 01 FF 4D 14 75 E3 8B 45 08 89 06 8B 45 0C 89 46 04 8B C6 5D C3 }
	$_2e653d1007cb9fdcb2c86c40c25b728d = { 55 8B 6C 24 08 8B 45 18 57 8B 38 85 FF 74 42 53 56 8B 37 83 7E 0C 01 8B 5F 08 75 2D C7 46 0C 02 00 00 00 A1 E0 ?? ?? ?? 85 C0 74 06 56 FF D0 83 C4 04 8B 4D 18 6A 00 57 51 E8 ?? ?? ?? ?? 6A ?? 56 E8 ?? ?? ?? ?? 83 C4 14 8B FB 85 DB 75 C2 5E 5B 5F 5D C3 }
	$_d51f0612d707041900e8ba2d9b4fbeba = { 56 57 8B F8 0F ?? ?? 50 33 F6 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 31 0F BE 17 0F ?? ?? ?? 47 8D 0C B6 50 8D 74 4A D0 E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 E4 85 F6 74 11 80 3F 24 75 0C 8B 4C 24 0C 47 89 39 5F 8B C6 5E C3 5F 33 C0 5E C3 }
	$_67a4fee29a85021f8e5b9f5282e0c00d = { 55 8B EC 51 83 65 FC 00 53 56 57 BF 70 C2 ?? ?? 57 8B F1 E8 20 32 05 00 59 50 8D 5E 04 57 8B CB E8 F1 AE FF FF FF 75 0C 8B CE E8 2E 00 00 00 80 7E 22 00 75 15 BE D4 C5 ?? ?? 56 E8 F8 31 05 00 59 50 56 8B CB E8 8B C4 FF FF 8B 4D 08 53 E8 F8 C0 FF FF 8B 45 08 5F 5E 5B C9 C2 08 00 }
	$_5058e734e13e84d6ebf1b3801e8784c4 = { 8B 44 24 04 56 8B 30 50 C7 86 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 31 F6 86 ?? ?? ?? ?? ?? 75 1C 39 86 ?? ?? ?? ?? 75 14 8B 86 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 C7 86 ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 5E C3 }
	$_6d9ace4c642ed6758bf0f9971973afe7 = { 8B 4C 24 04 8B 41 04 83 E8 02 74 24 83 E8 15 74 03 33 C0 C3 8B 41 18 8B 4C 24 0C 8B 54 24 08 51 52 83 C0 08 50 6A 17 E8 ?? ?? ?? ?? 83 C4 10 C3 8B 41 18 8B 4C 24 0C 8B 54 24 08 51 52 83 C0 04 50 6A 02 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	$_67e9b74d02dc07c094cbf605b2a228df = { 55 8B EC A1 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 05 8B 40 04 EB 02 33 C0 56 8B 75 0C 81 FE FF 00 00 00 77 16 85 C0 74 12 83 38 00 75 0D 8B 4D 08 8A 14 31 88 11 89 08 5E 5D C3 8B 45 08 50 E8 ?? ?? ?? ?? 83 C4 04 5E 5D C3 }
	$_fc0ba022b38de63b1771f3981f2aec8d = { 56 57 8B 7C 24 0C 8B 37 83 7E 48 00 74 0D 6A 02 6A 03 56 E8 08 39 01 00 83 C4 0C 8B 44 24 14 8B 4C 24 10 50 8B D7 E8 F5 FE FF FF 8B F8 83 C4 04 85 FF 74 03 FF 47 10 83 7E 48 00 74 0B 6A 03 56 E8 1B 39 01 00 83 C4 08 8B C7 5F 5E C3 }
	$_e1f0c5faf11227dc8abb08098a0dec60 = { 8B 10 8B 40 04 85 D2 75 05 2B 41 04 EB 1E 56 8B 71 04 C1 EE 02 C1 E8 02 3B C6 5E 74 03 32 C0 C3 50 FF 31 52 E8 84 55 05 00 83 C4 0C F7 D8 1B C0 40 C3 }
	$_60ca2de83ad930c885e27278555263f7 = { 8B 44 24 04 53 8B 5C 24 0C 55 56 57 8B BB B0 03 00 00 8B 4F 04 8B 2F 50 51 57 E8 51 F8 FF FF 83 C4 0C F7 D8 1B F6 8B 83 B0 03 00 00 83 E6 E5 83 C6 1B 3B F8 75 1D 3B 28 74 19 C7 83 AC 03 00 00 00 00 00 00 8B 10 8B 02 6A 00 50 E8 60 F8 FD FF 83 C4 08 5F 8B C6 5E 5D 5B C3 }
	$_b786b62b54d360c2656deb96d1414a29 = { 83 EC 18 A1 ?? ?? ?? ?? 33 C4 89 44 24 14 8D 04 24 50 56 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 23 8D 4C 24 04 51 56 6A 17 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 0F 8B 4C 24 14 33 CC E8 ?? ?? ?? ?? 83 C4 18 C3 8B 4C 24 14 33 CC B8 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	$_2e008c0acb07b5d984d8bd08429996be = { E8 4B FF FF FF 83 3D D0 9D 49 00 00 75 2D 6A 50 68 D8 9D 49 00 E8 66 18 00 00 83 C4 08 C7 05 68 70 49 00 D8 9D 49 00 E8 44 10 01 00 A3 70 70 49 00 C7 05 D0 9D 49 00 01 00 00 00 C3 }
	$_fcfe335b7f1a8c9c1376f335732ca117 = { 6A 08 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 10 83 65 FC 00 8B 75 08 89 45 EC 3B 75 0C 74 37 56 FF 75 10 FF 75 14 E8 ?? ?? ?? ?? 83 45 10 ?? 83 C4 0C 83 C6 ?? EB E3 8B 75 EC EB 0C 6A 01 8B CE E8 ?? ?? ?? ?? 83 C6 ?? 6A 00 3B 75 10 75 ED 6A 00 E8 ?? ?? ?? ?? 8B 45 10 E8 ?? ?? ?? ?? C3 }
	$_5927ae4cd6c8c874a4f2c6ed2ed5ada9 = { 6A 08 FF 15 ?? ?? ?? ?? 83 C4 04 85 C0 75 01 C3 8B 4C 24 08 56 8B 74 24 08 C7 40 04 00 00 00 00 89 08 85 F6 74 18 8B 4E 04 8B D6 85 C9 74 0A 90 8B D1 8B 4A 04 85 C9 75 F7 89 42 04 8B C6 5E C3 }
	$_a7738ecb4405da560e36ca41efe6247f = { 55 8B EC 8B 45 08 56 8B F1 C7 06 00 00 00 00 C7 46 04 00 00 00 00 85 C0 74 2B 8B 4D 10 F6 C1 26 74 14 51 8B 4D 0C 51 50 8B CE E8 71 FF FF FF 8B C6 5E 5D C2 0C 00 8B 55 0C 56 51 6A 00 52 50 FF 15 24 80 ?? ?? 8B C6 5E 5D C2 0C 00 }
	$_ed8edf5c794dc63d2efcd470ea6945c6 = { 57 53 FF 15 ?? ?? ?? ?? 8B F8 83 C4 04 85 FF 75 05 8D 47 1B 5F C3 8B 44 24 0C 53 50 57 E8 ?? ?? ?? ?? 8B 4C 24 14 83 C4 0C 89 BE ?? ?? ?? ?? 89 9E ?? ?? ?? ?? 89 8E ?? ?? ?? ?? 83 8E ?? ?? ?? ?? ?? 33 C0 5F C3 }
	$_cb2cbc0325d73b48202beb11300e7e32 = { 8B 44 24 04 56 33 C9 8B D0 87 0A 8B 74 24 0C 83 7E 0C 00 75 27 57 50 8D 46 10 50 E8 20 FF FF FF 8B F8 8B 46 0C 83 C4 08 85 C0 74 0C 83 F8 FF 74 07 50 FF 15 ?? ?? ?? ?? 89 7E 0C 5F 8B 76 0C 85 F6 74 07 56 FF 15 ?? ?? ?? ?? 5E C3 }
	$_2986cdabeb4c6bf30c83a257356dfbfd = { 8B 44 24 04 83 E8 02 74 27 83 E8 15 74 0F 68 3F 27 00 00 FF 15 ?? ?? ?? ?? 83 C8 FF C3 8B 44 24 0C 8B 4C 24 08 50 51 E8 D4 FD FF FF 83 C4 08 C3 8B 54 24 0C 8B 44 24 08 52 50 E8 01 FD FF FF 83 C4 08 C3 }
	$_c712147feae7f344a923b65120c82b69 = { 55 8B EC 53 8B 5D 08 56 8B F1 8B 46 04 3B D8 74 22 57 8B 7D 0C 57 53 50 E8 33 29 04 00 8B 45 14 57 53 50 FF 55 10 83 C4 18 01 7E 04 5F 5E 5B 5D C2 10 00 8B 4D 0C 01 4E 04 5E 5B 5D C2 10 00 }
	$_662dd8a0aaa0188296474f8bb5b247e5 = { 55 8B EC 51 56 8B F1 8B 46 04 85 C0 74 0E 50 FF 15 74 82 ?? ?? C7 46 04 00 00 00 00 8B 06 85 C0 74 0D 50 FF 15 20 80 ?? ?? C7 06 00 00 00 00 8B 4D 10 8B 55 0C 8D 45 FC 50 8B 45 08 56 6A 00 51 6A 00 6A 00 6A 00 52 50 FF 15 28 80 ?? ?? 5E 8B E5 5D C2 0C 00 }
	$_e52215ae3384ede8c4c8f687399dd85e = { 55 8B EC 56 8B F1 8B 46 04 85 C0 74 0E 50 FF 15 74 82 ?? ?? C7 46 04 00 00 00 00 8B 06 85 C0 74 0D 50 FF 15 20 80 ?? ?? C7 06 00 00 00 00 8B 45 10 8B 4D 0C 8B 55 08 56 50 6A 00 51 52 FF 15 24 80 ?? ?? 5E 5D C2 0C 00 }
	$_53c9a24605330f6a8f80b1301459916b = { 55 8B EC 51 56 8B 75 0C 57 8B 7D 08 56 57 C7 45 FC 00 00 00 00 FF 15 90 82 ?? ?? 85 C0 74 14 8D 4D FC 51 50 FF 15 8C 82 ?? ?? 8B 45 FC 5F 5E 8B E5 5D C3 FF 15 00 81 ?? ?? 50 56 57 68 C8 8B ?? ?? 68 B0 8B ?? ?? 6A 02 E8 E3 4D 00 00 8B 45 FC 83 C4 18 5F 5E 8B E5 5D C3 }
	$_9f53b5ece91af8198d6c70e32c4bd815 = { 55 8B EC 83 EC 08 53 56 8B F1 57 8B 3E 33 DB 3B FB 74 35 8B 0E 3B CB 74 0F 8B 41 14 89 06 3B C3 75 03 89 5E 04 89 59 14 89 5D F8 E8 ?? ?? ?? ?? 8B 4F 18 89 45 FC 53 8D 45 F8 50 57 53 FF D1 8B 3E 83 C4 10 3B FB 75 CB 5F 5E 5B 8B E5 5D C3 }
	$_2670fd3630244cb96344d3f30442dc9c = { 83 B8 ?? ?? ?? ?? ?? 74 08 8B 88 B8 00 00 00 EB 17 83 B8 ?? ?? ?? ?? ?? 74 08 8B 88 A8 00 00 00 EB 06 8B 88 98 00 00 00 8B 80 C0 00 00 00 50 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C C3 }
	$_5c33be79f4e58fd9face4eea3afbe329 = { 55 8B EC 80 78 08 04 74 04 32 C0 EB 31 56 8B 30 85 F6 75 04 32 C0 EB 25 8B 40 08 C1 E8 08 A8 01 75 09 56 E8 B8 4E 05 00 59 EB 05 8B 06 83 C6 04 8B CE 03 C8 8B 45 08 89 37 89 08 B0 01 5E 5D C2 04 00 }
	$_1c26ac4adafddd7f8d0ad0c57ac245f9 = { 55 8B EC 51 56 57 8B 7D 0C 33 D2 89 55 FC 39 57 10 74 2E 8B 45 10 83 78 14 10 8B 48 10 72 02 8B 00 51 52 50 8B CF E8 E5 F7 FF FF 8B 75 08 6A FF 50 56 8B CF E8 17 C6 FF FF 5F 8B C6 5E 8B E5 5D C3 8B 75 08 6A FF 52 C7 46 14 0F 00 00 00 89 56 10 57 8B CE 88 16 E8 08 4F FF FF 5F 8B C6 5E 8B E5 5D C3 }
	$_beb1b38f69d71ae9df32d2e9a6961d46 = { 55 8B EC 83 EC 28 A1 D0 73 49 00 33 C5 89 45 FC DD 45 08 83 65 D8 00 51 51 DD 1C 24 68 F4 CA 48 00 8D 45 DC 6A 20 50 E8 18 4F 05 00 8D 4D DC 8D 44 05 DC 8B D1 83 C4 14 3B D0 73 0D 80 39 2C 75 03 C6 01 2E 41 3B C8 72 F3 8D 45 DC 50 8B CE E8 A4 B1 FF FF 8B 4D FC 33 CD 8B C6 E8 CF 2C 05 00 C9 C3 }
	$_04c0d40e3611fc0497aa6c3ceff64ecf = { 56 57 8D 7B 68 57 E8 45 37 02 00 8B F0 83 C4 04 85 F6 74 2E 8B 83 90 00 00 00 6A 01 89 06 56 C7 40 08 00 00 00 00 E8 05 57 00 00 6A 00 56 E8 ED D7 FF FF 57 E8 17 37 02 00 8B F0 83 C4 14 85 F6 75 D2 5F 5E C3 }
	$_d9edd004e1943d2eddb252c8d2346537 = { 80 38 00 53 56 57 BB 01 00 00 00 8B F1 8B F8 74 49 8A 07 3C 20 74 27 3C 3F 75 02 33 DB 3C 80 72 19 0F B6 C0 50 68 60 4D ?? ?? 6A 04 56 E8 DE 19 FE FF 83 C4 10 83 C6 03 EB 1A 88 06 EB 15 85 DB 74 0E 66 C7 06 25 32 C6 46 02 30 83 C6 03 EB 04 C6 06 2B 46 47 80 3F 00 75 B7 5F C6 06 00 5E 5B C3 }
	$_06c0d04c2e9efecf2d0b42146b86ec9f = { 8B 44 24 04 8B 10 83 BA ?? ?? ?? ?? ?? 74 37 83 B8 ?? ?? ?? ?? ?? 74 08 8B 88 ?? ?? ?? ?? EB 06 8B 88 ?? ?? ?? ?? 56 8B 70 ?? 56 8B B0 ?? ?? ?? ?? 56 83 C0 ?? 50 51 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 18 5E C3 }
	$_98f8a96a3fcf2b08786a3a3c72a6fcb6 = { 8B 4C 24 08 83 B9 18 03 00 00 00 74 06 B8 01 00 00 00 C3 83 B9 ?? ?? ?? ?? ?? 75 2D 8B 81 ?? ?? ?? ?? 85 C0 74 23 8B 00 85 C0 74 1D 8B 00 33 D2 3B 44 24 04 0F 94 C2 8B C2 85 C0 74 0C B8 01 00 00 00 89 81 ?? ?? ?? ?? C3 33 C0 C3 }
	$_71ac8219c8cf13cfe492f164b8316b8f = { 55 8B EC 83 EC 08 56 57 8B 3D F8 81 ?? ?? 8B F1 6A 01 8D 46 1C 50 FF D7 85 C0 75 42 6A 01 8D 4E 20 51 FF D7 85 C0 75 36 8B 56 14 50 50 50 52 FF 15 08 82 ?? ?? 85 C0 75 25 FF 15 00 81 ?? ?? 8B F0 89 75 F8 E8 07 6F 00 00 89 45 FC 85 F6 74 0E 68 88 BB ?? ?? 8D 45 F8 50 E8 12 DB FF FF 5F 5E 8B E5 5D C3 }
	$_837963b46890b527b3e616ec64f5a680 = { 8B ?? ?? ?? 85 ?? 74 15 8B ?? 85 C0 74 0F 8B ?? ?? ?? 39 ?? 74 0A 8B 40 08 85 C0 75 F5 33 C0 C3 6A 00 50 ?? E8 ?? ?? ?? ?? 83 C4 0C B8 01 00 00 00 C3 }
	$_5bb7cab17e1f0256defbd7ecc3ba587e = { 56 8B 74 24 0C 85 F6 74 0C 83 FE 03 75 0C E8 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 74 11 8B 4C 24 10 8B 54 24 08 51 56 52 FF D0 5E C2 0C 00 B8 01 00 00 00 5E C2 0C 00 }
	$_d1f6d8a73d632df694f46424fa6a0ea0 = { 55 8B EC 8B 45 08 56 8B F1 8B 48 10 85 C9 75 0A 89 4E 10 8B C6 5E 5D C2 04 00 3B C8 8B C1 8B 10 8B 02 75 0D 56 FF D0 89 46 10 8B C6 5E 5D C2 04 00 6A 00 FF D0 89 46 10 8B C6 5E 5D C2 04 00 }
	$_56da247706fe397df62a72f18c30d84e = { 56 8B 74 24 08 85 F6 74 13 83 7E 48 00 74 0D 6A 02 6A 03 56 E8 27 33 01 00 83 C4 0C 57 8B 7C 24 10 FF 4F 10 75 12 8B 07 50 E8 12 ED 00 00 57 FF 15 44 70 ?? ?? 83 C4 08 5F 85 F6 74 11 83 7E 48 00 74 0B 6A 03 56 E8 35 33 01 00 83 C4 08 5E C3 }
	$_9755a0d822153bf3308fd61335ff2f1c = { 8B 4E 08 53 8B 18 8B C1 57 89 4E 0C 8D 78 01 90 8A 10 40 84 D2 75 F9 2B C7 74 0B 80 7C 01 FF 2E 75 04 88 54 01 FF 8B 4E 08 8A 01 84 C0 74 1D 90 41 24 80 75 09 8A 01 84 C0 75 F5 5F 5B C3 68 64 C5 ?? ?? 53 E8 C7 91 00 00 83 C4 08 5F 5B C3 }
	$_b24621d7eb7bece490cf2a1153dc0168 = { 55 8B EC 8B 45 08 53 8B 5D 0C 3B C3 74 41 56 57 8D 78 04 8B 37 85 F6 74 2A 8D 46 04 83 C9 FF F0 0F C1 08 75 1E 8B 16 8B 42 04 8B CE FF D0 8D 4E 08 83 CA FF F0 0F C1 11 75 09 8B 06 8B 50 08 8B CE FF D2 83 C7 08 8D 47 FC 3B C3 75 C6 5F 5E 5B 5D C3 }
 condition:
     5 of them // out of 69
     
}
