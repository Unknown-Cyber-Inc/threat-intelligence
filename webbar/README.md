**Webbar - YARA rules generated by malware genomic analysis**

The rules were generated using 2 samples:
    604e2343529c40c28a0a448fafc775078a98655e
    465d110be4cf9f067b1392e9e4e68d1f97e1dbfd

MAGIC used the following procedure selection criteria:

   - Select clones,
   - with between 5 and 50 blocks, and
   - between 10 and 100 instructions, and
   - between 50 and 100 bytes

MAGIC selected 5 shared functions that matched this criteria.


There are two Yara rules, both use the same selected procedures. They differ in the conditions in how the select the number of procedures that should match.
   - Version v1: Requires a subset (greater than one) of the  selected procedures to be match.
   - Version v2: Requires ANY one of the selected procedures to be present

So rule v1 is slightly more strict than v2. 


##CONTENTS##

   - CythMAGIC_webbar_v1.yar: A bit stringent rule. 
   - CythMAGIC_webbar_v2.yar: Most relaxed rule.
   


