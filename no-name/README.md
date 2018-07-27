**Unnamed malware - YARA rules generated by malware genomic analysis**

This folder contains Yara rules automatically generated by MAGIC for a cluster of malware with no discernible name. It is likely this not a prominent malware family.

The rules were generated using the following samples, though we have over 2,000 variants in our collection:

    4f62d52275fffd5a67165bdc45ed7769d1cf3674
    8866630f48b6a91319b667bf628d09d259bee9b6
    07a55715d7a112c1588c1357366572aa43e55d99
    31f479ab5ae812a7a653fb754f3af70edb631859
    ffd6f82d6f71d5c22ca65839eada0f2f10028e63

MAGIC used the following procedure selection criteria:

   - Select clones,
   - with between 5 and 50 blocks, and
   - between 10 and 100 instructions, and
   - between 50 and 100 bytes
   - and a coverage of 80-100%

MAGIC selected 39 shared functions that matched this criteria. Published in this report are two version of rules generated by MAGIC. The two versions differ in the condition sections where it gives the number of selected procedures that should be present in the binary to be considered matched.

   - Version v1: Requires any 10 of the selected procedures to be present
   - Version v2: Require that ANY one of the selected procedures to be present

Clearly rule v1 is more strict than v2.

##CONTENTS##

* yara/ - contains yara rules
   - CythMAGIC_ffd6f_v1.yar: A bit stringent rule. 
   - CythMAGIC_ffd6f_v2.yar: Most relaxed rule. 

