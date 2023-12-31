**coinminer - YARA rules generated by malware genomic analysis**

This folder contains Yara rules automatically generated by MAGIC for a cluster of malware called Coinminer, Bitcoinminer, WisdomEye, Zusy

The rules were generated using 23 samples, from a collection of over 80 similar malware. Some of the samples used are:

    0f1ac565c4084e9da3db854a2ebc6c43c36c6c4b
    1cda25075a60711607d6ad989d0c572c4ccd1a7c
    2738179196073a26ce3fb26d778e62b9a4cf8272    
    2de0ce96326d0a021291b78a5ae759088e563bff
    36e8b076e80b3e92b753e476fb4d73c2d68997d1
    56a6b0c1a7f09e4c81d00bf5324d352a489a8a74
    6495f626112a28b6eb069ebad34064b7e098811e
    a97df05e5a58509e99ed4434e639db378c43711a
    cf9d1e9b6a3b33907722cbc7fa507663319451a7
    fdf58436925d54e7af14a088c1e324c3e4149adf


MAGIC used the following procedure selection criteria:

   - Select clones,
   - with between 5 and 50 blocks, and
   - between 10 and 100 instructions, and
   - between 50 and 100 bytes

MAGIC selected 8 shared functions that matched this criteria.

There are two Yara rules, both use the same selected procedures. They differ in the conditions in how the select the number of procedures that should match.
   - Version v1: Requires a subset (greater than one) of the  selected procedures to be match.
   - Version v2: Requires ANY one of the selected procedures to be present

So rule v1 is slightly more strict than v2. 

##CONTENTS##

   - CythMAGIC_fcf02_v1.yar: A bit stringent rule. 
   - CythMAGIC_fcf02_v2.yar: Most relaxed rule.
   


