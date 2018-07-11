rule Cyth_VPNFilter_MIPS_stage3
{
 meta:

	author = "Cythereal, Inc"
	description = "VPN Filter - version _v5"
	cluster_id = "MIPS_stage3"
	hash1 = "a5e0d0ebe41683619d1b9802149f0403b1a7d8be"
	criteria = "clones with 50 <= bytes <= 3000, 4 <= total_occ <= 10"
 strings:

	$_18714e67f25fdd85e3accb3cfdd1b175 = { 3C 1C 00 ?? ?? ?? ?? ?? 03 99 E0 21 27 BD FF B8 AF BF 00 40 AF B5 00 3C AF B4 00 38 AF B3 00 34 AF B2 00 30 AF B1 00 2C AF B0 00 28 AF BC 00 10 8C F2 00 34 24 F0 00 38 00 80 A8 21 00 A0 A0 21 00 C0 98 21 8F 99 ?? ?? 00 E0 88 21 27 A4 00 18 8F 85 ?? ?? 16 40 00 0B 02 00 30 21 03 20 F8 09 00 00 00 00 8F BC 00 10 00 00 00 00 8F 99 ?? ?? 00 00 00 00 03 20 F8 09 02 00 20 21 8F BC 00 10 00 00 00 00 8F 99 ?? ?? 02 A0 20 21 02 80 28 21 02 60 30 21 03 20 F8 09 02 20 38 21 8F BC 00 10 00 40 80 21 8F 99 ?? ?? 27 A4 00 18 16 40 00 04 24 05 00 01 03 20 F8 09 00 00 00 00 8F BC 00 10 02 00 10 21 8F BF 00 40 8F B5 00 3C 8F B4 00 38 8F B3 00 34 8F B2 00 30 8F B1 00 2C 8F B0 00 28 03 E0 00 08 27 BD 00 48 }
 condition:

	
	 any of them // out of 1 strings
}
