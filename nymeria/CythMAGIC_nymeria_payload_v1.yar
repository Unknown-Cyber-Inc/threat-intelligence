rule CythMAGIC_nymeria_payload_v1
{
 meta:

	author = "Cythereal, Inc"
	description = ""
	cluster_id = "f784e4328a810c63d00a7e94620cb2bc96e418ce"
	size_of_cluster = "1"
	criteria = "clones with 5 <= 50 <= block_counts 10 <= 100 <= instr_counts 50 <= 100 <= byte_counts 0.8 <= 1 <= coverage"
 strings:

	$_d1c6b9691cc58a90ae56eed1cd412b15 = { 53 56 57 8B F9 8D 77 14 56 FF 15 ?? ?? ?? ?? 8D 47 34 FF 30 50 FF 15 ?? ?? ?? ?? 3D F6 01 00 00 75 07 33 DB 39 5F 0C 74 02 B3 01 56 FF 15 ?? ?? ?? ?? 5F 5E 8A C3 5B C3 }
	$_681949e5b322c570dfd431f90bcc585d = { 55 8B EC 56 8B F1 80 7E 09 00 0F 85 ?? ?? ?? ?? 57 6A ?? E8 ?? ?? ?? ?? 8B F8 59 85 FF 74 1B FF 75 08 8B CF E8 ?? ?? ?? ?? 8B 46 04 89 47 ?? 89 7E 04 5F FF 06 5E 5D C2 04 00 33 FF EB EB  }
	$_a4d9b0b38fd016d39f48f7cab5c63695 = { 55 8B EC 56 8B F1 83 7E 0C 04 74 3F E8 ?? ?? ?? ?? 6A 10 C7 46 0C 04 00 00 00 E8 ?? ?? ?? ?? 8B D0 59 85 D2 74 32 8B 45 08 8B 08 89 0A 8B 48 04 89 4A 04 8B 48 08 89 4A 08 8B 40 0C 89 42 0C FF 00 89 56 08 8B C6 5E 5D C2 04 00 FF 75 08 8B 4E 08 E8 ?? ?? ?? ?? EB EC 33 D2 EB E5 }
	$_48e05265a5b4309dc13740975aa2e461 = { 55 8B EC 53 33 DB 56 8B 75 08 8A D3 8B 0E 8D 41 01 89 06 3B 0D ?? ?? ?? ?? 7F 37 85 C9 7E 33 C1 E1 04 03 0D ?? ?? ?? ?? 85 C9 74 1A 48 A3 ?? ?? ?? ?? 8B 41 04 8B 00 66 39 58 08 75 05 83 38 21 74 0C 84 D2 74 C6 5E 33 C0 5B 5D C2 04 00 B2 01 EB F0 8B CB EB D2 }
	$_d5a923fc3509d3d0c119b4830c91f3c6 = { 55 8B EC 56 57 8B 7D 08 57 8B F1 E8 ?? ?? ?? ?? 84 C0 74 06 5F 5E 5D C2 04 00 8D 47 01 50 E8 ?? ?? ?? ?? 83 3E 00 89 46 08 74 08 FF 36 E8 ?? ?? ?? ?? 59 8B 46 08 33 C9 6A 02 5A F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 59 33 C9 89 06 66 89 0C 78 EB BF }
	$_30c31a7047a647140a1d942cd7adea4b = { 55 8B EC 56 57 8B 7D 08 57 8B F1 E8 ?? ?? ?? ?? 84 C0 75 28 8D 47 01 50 E8 ?? ?? ?? ?? 83 3E 00 89 46 08 74 08 FF 36 E8 ?? ?? ?? ?? 59 FF 76 08 E8 ?? ?? ?? ?? 89 06 59 C6 04 38 00 5F 5E 5D C2 04 00 }
	$_a1bf1b03d68c51f837451998186a846b = { 55 8B EC 56 8B F1 E8 ?? ?? ?? ?? 84 C0 74 06 8B 0E 85 C9 75 32 6A 10 E8 ?? ?? ?? ?? 8B D0 59 85 D2 74 2C 8B 45 08 8B 08 89 0A 8B 48 04 89 4A 04 8B 48 08 89 4A 08 8B 40 0C 89 42 0C FF 00 89 16 8B C6 5E 5D C2 04 00 51 E8 ?? ?? ?? ?? EB C6 33 D2 EB EB }
	$_9f62d904bc38d2f7c71f06834df06142 = { 55 8B EC 56 8B 75 08 33 C0 83 7E 08 01 57 0F 87 ?? ?? ?? ?? 8B 4E 04 6A FF 8B 09 6A FF 50 6A FF 6A 00 E8 ?? ?? ?? ?? 50 6A 00 E8 ?? ?? ?? ?? 8B 75 0C 8B CE 8B F8 E8 ?? ?? ?? ?? 89 3E 5F C7 46 0C 01 00 00 00 33 C0 5E 5D C2 08 00  }
	$_735149299f0dd3685bef743dad1a8f61 = { 55 8B EC A1 ?? ?? ?? ?? 8B 4D 18 83 F8 01 0F 85 ?? ?? ?? ?? 8B 45 08 83 F8 FF 74 03 89 41 58 8B 45 0C 83 F8 FF 74 03 89 41 5C 8B 45 10 85 C0 7E 03 89 41 60 8B 45 14 85 C0 7E 03 89 41 64 5D C2 14 00  }
	$_055df45b2947b1e688b6f5498c609f74 = { 8B 01 8B 90 0C ?? ?? ?? 3B 90 10 02 00 00 74 03 32 C0 C3 33 C9 56 85 D2 7E 1B 05 ?? ?? ?? ?? 8B 30 85 F6 78 14 3B B0 ?? ?? ?? ?? 7D 0C 41 83 C0 04 3B CA 7C EA B0 01 5E C3 32 C0 5E C3 }
	$_61ab35e986b8cceaab91dc7f4f576a15 = { 55 8B EC 8B 4D 0C 83 EC 10 53 E8 ?? ?? ?? ?? 8D 45 F8 50 6A 01 33 DB 53 68 ?? ?? ?? ?? 68 01 00 00 80 FF 15 20 ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 32 C0 5B C9 C3  }
	$_85cf4464d119d1d2a5c72ae0db597fa2 = { 55 8B EC 57 8B F9 83 7F 08 00 75 47 56 6A 28 E8 ?? ?? ?? ?? 8B F0 59 85 F6 74 41 8B CE E8 ?? ?? ?? ?? FF 75 08 8B CE E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? FF 76 04 FF 36 FF 15 ?? ?? ?? ?? 83 66 24 00 8B 47 04 85 C0 74 0F 89 70 24 FF 47 0C 89 77 04 5E 5F 5D C2 04 00 89 37 EB F0 33 F6 EB C2 }
	$_d05934f47b2a4ec7b1d52091f60f9ce1 = { 55 8B EC 56 57 8B F1 33 FF 6A 0C 39 7E 04 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 85 C0 74 0C FF 75 08 8B C8 E8 ?? ?? ?? ?? 8B F8 89 3E FF 46 08 89 7E 04 5F 5E 5D C2 04 00  }
	$_461df554dabcd64cba867a761c194671 = { A1 ?? ?? ?? ?? 56 8B F1 3D 00 10 00 00 76 35 8B 8E ?? ?? ?? ?? 83 25 ?? ?? ?? ?? ?? 85 C9 74 2A 8B 46 08 6B C0 64 33 D2 F7 76 10 50 FF 76 08 FF 76 0C FF D1 83 C4 0C 85 C0 75 0F C6 86 ?? ?? ?? ?? ?? 5E C3 40 A3 ?? ?? ?? ?? 5E C3 }
	$_3649170b35a76081c6939e884e149de7 = { 55 8B EC 56 8B F1 83 7E 04 00 75 12 FF 75 08 8B 0E E8 ?? ?? ?? ?? FF 46 04 5E 5D C2 04 00 80 7E 0D 00 75 29 57 6A 18 E8 ?? ?? ?? ?? 8B F8 59 85 FF 74 2B FF 75 08 83 67 08 00 8B CF E8 ?? ?? ?? ?? 8B 46 08 89 47 10 89 7E 08 5F EB C9 FF 75 08 8B 4E 08 E8 ?? ?? ?? ?? C6 46 0D 00 EB B8 33 FF EB DF }
	$_95599885cb206eaaf1e041ede66c9b86 = { 55 8B EC FF 75 08 B9 10 18 4C 00 E8 7B F7 FF FF 8B 55 0C 8B C8 85 D2 74 14 A1 70 18 4C 00 8B 04 88 8B 00 83 78 18 00 0F 85 8A 3C 06 00 83 0D 38 18 4C 00 FF 0F B7 4D 14 FF 75 10 0F B7 C2 C1 E1 10 0B C8 51 6A 06 FF 75 08 FF 15 60 D5 48 00 5D C2 10 00  }
	$_95e000013cd982e74cf678e5ca498880 = { 55 8B EC F6 45 08 02 56 8B F1 0F 84 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 8D 7E FC FF 37 6A 10 5A E8 ?? ?? ?? ?? F6 45 08 01 74 07 57 E8 ?? ?? ?? ?? 59 8B C7 5F 5E 5D C2 04 00 E8 ?? ?? ?? ?? F6 45 08 01 74 07 56 E8 ?? ?? ?? ?? 59 8B C6 E9 ?? ?? ?? ?? }
	$_f05748a0f21e3f5b16bd61ef0b81e27f = { 55 8B EC 53 56 33 F6 57 8B 7D 08 8B DE 66 8B 0C 77 E8 25 00 00 00 85 C0 74 03 46 EB F0 0F B7 04 77 66 85 C0 74 08 66 89 04 5F 43 46 EB EF 33 C0 66 89 04 5F 5F 5E 5B 5D C2 04 00 }
	$_16b807cf28e716268d8ae04313d60287 = { 55 8B EC 51 57 8B FA 3B CF 0F 85 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F0 8D 45 FC 50 57 68 04 01 00 00 56 FF 15 10 ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 59 5E 5F C9 C3  }
	$_24c988c6146676127e1c1dd518467b39 = { 55 8B EC 51 57 8B 7D 0C 89 4D FC 85 FF 74 40 53 0F B7 19 56 0F B7 71 02 7E 2C 33 C9 8B 45 08 33 D2 0F B6 04 01 03 C3 BB F1 FF 00 00 F7 F3 8B DA 33 D2 8D 04 1E BE F1 FF 00 00 F7 F6 41 8B F2 3B CF 7C D9 8B 4D FC C1 E6 10 03 F3 89 31 5E 5B 5F C9 C2 08 00 }
	$_f1a8d71f8b6453a239d524166f1d83d2 = { 55 8B EC 83 EC 18 83 65 EC 00 83 65 F4 00 56 83 CE FF 56 8D 45 EC 50 FF 75 0C C7 45 F8 01 00 00 00 FF 75 08 E8 ?? ?? ?? ?? 85 C0 78 14 8D 4D EC E8 1B 00 00 00 84 C0 8B 45 10 0F 95 C1 88 08 33 F6 8D 4D EC E8 ?? ?? ?? ?? 8B C6 5E C9 C2 0C 00 }
	$_41fe8317c03b815181019910b15a4727 = { 85 C0 0F 84 ?? ?? ?? ?? 83 C8 FF E9 ?? ?? ?? ?? 55 8B EC 8B 51 04 56 8B 75 08 8B 46 04 85 D2 0F 84 ?? ?? ?? ?? 85 C0 74 17 8B 09 3B D0 ?? ?? ?? 8B 16 E8 12 00 00 00 59 5E 5D C2 04 00 ?? EB F0 85 D2 74 E5 33 C0 40 EB EF }
	$_a40d3018f2bdf656f5f01f273694bd2a = { 55 8B EC 56 8B F1 E8 ?? ?? ?? ?? 84 C0 74 0C 8B 0E 85 C9 74 06 51 E8 ?? ?? ?? ?? 6A 10 E8 ?? ?? ?? ?? 59 85 C0 74 0C FF 75 08 8B C8 E8 ?? ?? ?? ?? EB 02 33 C0 89 06 8B C6 5E 5D C2 04 00 }
	$_ff1cfe598b81454ade1df259960c2f04 = { 55 8B EC 57 8B 7D 08 57 E8 ?? ?? ?? ?? 59 85 C0 74 1D 56 8D 70 FF 85 F6 78 0D 66 8B 0C 77 E8 ?? ?? ?? ?? 85 C0 75 0D 33 C0 66 89 44 77 02 5E 5F 5D C2 04 00 4E 79 E3 EB EE }
	$_b97b6cdcfe38ab8481902f069db112af = { 55 8B EC 83 79 0C 05 75 27 8B 11 56 8B B2 10 02 00 00 83 FE 40 7D 1D 8B 45 08 89 84 B2 0C 01 00 00 8B 01 FF 80 10 02 00 00 B0 01 5E 5D C2 04 00 32 C0 EB F8 32 C0 EB F3 }
	$_e9c7f970ba25401fd6c888ba7063c792 = { 55 8B EC 8B 4D 10 53 56 E8 ?? ?? ?? ?? 8B 75 14 32 DB FF 36 8B 4D 0C E8 ?? ?? ?? ?? 0F B7 00 66 85 C0 74 1B 84 DB 75 17 66 3B 45 08 74 0D 8B 4D 10 50 E8 ?? ?? ?? ?? FF 06 EB D7 B3 01 EB F8 66 83 7D 08 00 B0 01 74 02 8A C3 5E 5B 5D C2 10 00 }
	$_950d292b4111b5988407b39ae0072ac7 = { 56 8B F1 B9 00 00 01 00 8B 86 ?? ?? ?? ?? 85 C0 74 04 3B C1 75 1B FF 76 1C 51 6A 01 FF B6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 A6 ?? ?? ?? ?? ?? 8B 8E ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 8A 04 01 41 89 8E ?? ?? ?? ?? 5E C3 }
	$_3fae6eea16c867c2efb9d35366a97957 = { 56 8B F1 8B 86 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 8B 86 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 8B 86 ?? ?? ?? ?? 5E 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 C3 }
	$_d608609f8e2b3275dcd0077678f62f76 = { 53 56 8B F1 33 DB 39 1E 74 0A FF 36 E8 ?? ?? ?? ?? 59 89 1E 8B 4E 10 85 C9 75 0B 39 5E 0C 75 11 88 5E 14 5E 5B C3 8B 01 51 FF 50 08 89 5E 10 EB EA FF 76 0C FF 15 ?? ?? ?? ?? 89 5E 0C EB E1 }
	$_663139eb9a3f6042c9af1ba0d7f0d2c0 = { 55 8B EC A1 ?? ?? ?? ?? 8B 4D 08 83 EC 0C 8B FF 85 C0 74 1C 8B 10 39 0A 74 05 8B 40 04 EB F1 8B 4D 0C 01 4A 04 8B 00 8B 40 08 8B E5 5D C2 08 00 51 89 4D F4 C7 45 F8 01 00 00 00 FF 15 3C ?? ?? ?? 89 45 FC 8D 45 F4 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC 8B E5 5D C2 08 00 }
	$_3d347e04c612ee3907aaa06e1c262be5 = { 56 8B F1 83 7E 0C 04 74 43 57 6A 10 E8 ?? ?? ?? ?? 8B F8 59 85 FF 74 36 8B CE E8 ?? ?? ?? ?? 8B 56 08 8B 0A 89 0F 8B 4A 04 89 4F 04 8B 42 08 89 47 08 8B 42 0C 89 47 0C FF 00 8B CE E8 ?? ?? ?? ?? 89 7E 08 C7 46 0C 04 00 00 00 5F 5E C3 33 FF EB E8 }
	$_68ac461f75d7f0702edd5859f564def0 = { 55 8B EC 8B 11 3B 51 1C 7D 19 8D 42 01 89 01 8B 41 18 8B 4D 08 FF 34 90 E8 ?? ?? ?? ?? B0 01 5D C2 04 00 8B 4D 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 32 C0 EB EB }
	$_a70f1074a8d1ea3f4949632f563ef76f = { 55 8B EC 56 8B F1 80 7E 09 00 0F 85 ?? ?? ?? ?? 6A 08 E8 ?? ?? ?? ?? 8B D0 59 85 D2 74 17 8B 4D 08 8B 09 89 0A 8B 46 04 89 42 04 89 56 04 FF 06 5E 5D C2 04 00 33 D2 EB EC  }
	$_34ac6391be9ec7e82e548b9d0e483f74 = { 55 8B EC 81 EC DC 00 00 00 8D 8D 24 FF FF FF 56 57 E8 ?? ?? ?? ?? FF 75 10 8D 8D 24 FF FF FF E8 ?? ?? ?? ?? 33 F6 39 75 0C 76 19 8B 7D 08 51 51 8D 8D 24 FF FF FF E8 99 FF FF FF 30 04 3E 46 3B 75 0C 72 EA 5F 5E C9 C2 0C 00 }
	$_7ce305a744fbb8e192508024c9548049 = { 55 8B EC 83 EC 0C 83 65 F4 00 83 65 FC 00 56 8B F1 8D 4D F4 E8 ?? ?? ?? ?? 84 C0 74 0C FF 36 8D 4D F4 E8 ?? ?? ?? ?? FF D0 83 7D F4 00 5E 74 09 FF 75 F4 FF 15 ?? ?? ?? ?? C9 C3 }
	$_37105b53b095712a15f82d426b26f72a = { 56 8B F1 83 7E 04 01 74 16 80 7E 0D 00 57 75 14 80 7E 0C 00 0F 84 ?? ?? ?? ?? C6 46 0D 01 5F FF 4E 04 5E C3 8B 4E 08 8B 79 10 85 C9 74 06 51 E8 ?? ?? ?? ?? 89 7E 08 C6 46 0D 00 EB D3  }
	$_fe8245e12b8b9e057b48598828d56795 = { 55 8B EC 56 8B F1 E8 ?? ?? ?? ?? 8B 45 0C 83 66 2C 00 83 66 30 00 89 46 28 A8 03 75 08 0D 00 20 00 00 89 46 28 FF 76 28 8B CE FF 75 08 E8 ?? ?? ?? ?? 84 C0 74 1C 8B CE E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? B0 01 5E 5D C2 08 00 32 C0 EB F7 }
	$_7ce7a2efb8cd1757ab6a5ef28cc8e6b1 = { 57 8B F9 C7 07 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 77 2C FF 15 ?? ?? ?? ?? FF 77 30 FF 15 ?? ?? ?? ?? FF 77 08 E8 ?? ?? ?? ?? 59 8D 47 14 50 FF 15 ?? ?? ?? ?? C7 07 ?? ?? ?? ?? 5F C3 }
	$_0abb5a4225a9f478a8851f3ec312a758 = { 55 8B EC 8B 4D 08 A1 ?? ?? ?? ?? 56 8B 04 88 57 8B 30 6A 0F FF 15 ?? ?? ?? ?? 83 7E 4C FF 8B F8 74 03 8B 7E 4C 57 FF 75 0C FF 15 34 ?? ?? ?? 6A 00 57 E8 ?? ?? ?? ?? 5F 5E 5D C2 08 00 }
	$_3d256682f24828bf4c00f29fb683e9e3 = { 55 8B EC 53 8B D9 6A 0C 83 63 04 00 83 63 08 00 E8 ?? ?? ?? ?? 59 85 C0 74 15 56 8B 75 08 57 8B F8 A5 A5 A5 5F 5E 89 03 8B C3 5B 5D C2 04 00 33 C0 EB F3 }
	$_524b0a58233cd8ef1e779969f7e7815d = { 55 8B EC 83 EC 28 53 56 57 8B D9 6A 08 59 BE ?? ?? ?? ?? 8D 7D D8 F3 A5 8B C2 8B 55 0C 8D 48 FF 66 A5 8B 75 08 89 45 FC 85 C9 78 1B 8B C6 83 E0 0F 0F AC D6 04 66 8B 44 45 D8 66 89 04 4B C1 EA 04 49 79 E8 8B 45 FC 33 C9 5F 0B F2 5E 66 89 0C 43 5B 75 04 B0 01 C9 C3 32 C0 C9 C3 }
	$_905e1aa93f68e1b0364ca2013518d2c6 = { 56 8B F1 57 8D 7E 30 83 3F 00 74 53 53 8D 5E 34 FF 33 53 FF 15 ?? ?? ?? ?? 3D F6 01 00 00 74 3E 83 C6 14 56 FF 15 ?? ?? ?? ?? 68 F6 01 00 00 FF 37 FF 15 ?? ?? ?? ?? 68 E8 03 00 00 FF 37 FF 15 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 68 F6 01 00 00 53 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 5B 5F 5E C3 }
	$_859f6b53d90a986802c1bf6e05f03193 = { 55 8B EC 53 56 8B 75 08 57 6A 05 33 DB 83 7E 08 01 5F 0F 87 ?? ?? ?? ?? 83 7E 08 00 0F 87 ?? ?? ?? ?? 53 57 E8 1E 00 00 00 8B 75 0C 8B CE 8B F8 E8 ?? ?? ?? ?? 89 3E 5F C7 46 0C 01 00 00 00 5E 33 C0 5B 5D C2 08 00   }
	$_00c6423bbace6f399dfe0c10b32ea5e4 = { 56 8B F1 83 7E 0C 05 74 05 83 C8 FF 5E C3 E8 C5 FE FF FF 84 C0 74 F2 8B 06 57 8B B0 0C 02 00 00 8B 50 08 33 FF 85 F6 7E 20 53 8D 98 0C 01 00 00 8B C2 99 F7 BB 00 FF FF FF 8B 0B 8D 5B 04 8B D0 0F AF CA 03 F9 4E 75 E8 5B 8B C7 5F 5E C3 }
	$_fab47ef1b1288dbfb9c1d3bd0a756d8e = { 55 8B EC 56 8B 75 08 57 8B F9 85 F6 74 24 6A EB 56 FF 15 ?? ?? ?? ?? 3B 47 ?? 73 16 8B 4F ?? 8B 0C 81 8B 09 85 C9 74 0A 39 31 75 06 5F 5E 5D C2 04 00 83 C8 FF EB F5 }
	$_b883d31bedc8b6d7f5b954b14ec40610 = { 83 79 0C 04 56 75 27 8B 41 08 68 ?? ?? ?? ?? 8B 30 56 E8 ?? ?? ?? ?? 59 59 85 C0 75 15 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 59 59 85 C0 75 04 32 C0 5E C3 B0 01 5E C3 }
	$_a8599baa9f7b24f5ebe3b84c67df1188 = { 55 8B EC 83 EC 0C 56 8B F1 33 C0 8D 4D F4 89 06 89 45 F4 89 45 FC E8 ?? ?? ?? ?? 84 C0 74 0B 56 8D 4D F4 E8 ?? ?? ?? ?? FF D0 83 7D F4 00 74 09 FF 75 F4 FF 15 ?? ?? ?? ?? 8B C6 5E C9 C3 }
	$_d84a6dd32e3155412330a05500f5c9e0 = { 55 8B EC 51 51 8B 45 08 53 8B 40 04 56 8B 30 57 8B F9 6A 05 8B CE 89 7D F8 89 45 FC E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 8B 45 08 33 DB 43 39 58 08 0F 85 ?? ?? ?? ?? 53 8B CE E8 ?? ?? ?? ?? 8B 75 0C 8B CE 8B F8 E8 ?? ?? ?? ?? 89 5E 0C 89 3E 5F 5E 33 C0 5B C9 C2 08 00   }
	$_2af77c536242b6ac98cd75b354a455d9 = { 56 8B F1 83 7E 0C 05 74 37 E8 ?? ?? ?? ?? 68 14 02 00 00 E8 ?? ?? ?? ?? 89 06 59 33 C9 89 08 8B 06 89 48 04 8B 06 89 48 08 8B 06 89 88 0C 02 00 00 8B 06 89 88 10 02 00 00 C7 46 0C 05 00 00 00 5E C3 }
	$_817b9a7b0ad9c33826256a1340d84e78 = { 55 8B EC 56 8B F1 56 FF 75 08 E8 ?? ?? ?? ?? 84 C0 74 1C 8B 06 5E 85 C0 74 19 8B 50 10 8B 4D 0C 8B 40 14 81 E2 00 FF 00 00 89 11 5D C2 08 00 33 C0 EB E2 33 C0 EB F4 }
	$_1a5e969d0d2d1ebdef63fda261aeb2ae = { 53 56 8B F1 83 7E 24 00 75 1C 33 DB 89 5E 24 39 5E 2C 75 1D 89 5E 2C 89 5E 30 89 5E 34 89 5E 38 88 5E 10 5E 5B C3 FF 76 24 E8 ?? ?? ?? ?? 59 EB D9 FF 76 2C E8 ?? ?? ?? ?? 59 EB D8 }
	$_8f3fa0c1826de1932e311a22ee7ad682 = { 55 8B EC 56 57 8B 7D 10 8B F1 85 FF 74 3D 83 FF FF 74 38 83 7D 08 00 74 32 E8 ?? ?? ?? ?? 8B CE 84 C0 0F 85 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 57 FF 75 08 89 7E 04 FF 36 E8 ?? ?? ?? ?? 8B 06 83 C4 0C C6 04 07 00 5F 5E 5D C2 0C 00 51 51 E8 ?? ?? ?? ?? EB F1  }
	$_1a84723633776ee37c8fc3961c8e9b4c = { 55 8B EC 56 57 8B 7D 08 8B F1 8B 47 04 8B 08 E8 ?? ?? ?? ?? 85 C0 0F 8E ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 86 18 03 00 00 8B 47 04 8B 08 E8 ?? ?? ?? ?? 6A 00 8B CE 89 86 10 03 00 00 C7 86 FC 00 00 00 02 00 00 00 E8 ?? ?? ?? ?? 5F 33 C0 5E 5D C2 08 00  }
 condition:
     5 of them // out of 53
}
