**Petya (cluster 1) - YARA rules generated by malware genomic analysis**

This folder contains Yara rules automatically generated by MAGIC. They were created using two samples of Petya.

    f152b026176d4eb1819cd55e7ace77c9cb3c3796
    9717cfdc2d023812dbc84a941674eb23a2a8ef06


MAGIC used the following procedure selection criteria:

   - Select clones,
   - with between 5 and 50 blocks, and
   - between 10 and 100 instructions, and
   - between 50 and 100 bytes
   - and a coverage of 80-100%

MAGIC selected 20 shared functions that matched this criteria.

It then generate two version of rules. The versions differed on the number of selected procedures that should be present in the binary to be considered matched.

   - Version v1: Requires any 7 of the 20 selected procedures to be present
   - Version v2: Require that ANY one of the selected procedures to be present

Clearly rule v1 is more strict than v2.

##CONTENTS##

* yara/ - contains yara rules
   - CythMAGIC_petya1_v1.yar: A bit stringent rule. Requires at least seven of the common procedures to be present for a match
   - CythMAGIC_petya1_v2.yar: Most relaxed rule. Requires 
