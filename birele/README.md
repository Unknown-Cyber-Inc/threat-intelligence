**Birele (packed and payload) - YARA rules generated by malware genomic analysis**

This folder contains Yara rules automatically generated by MAGIC for malware called Birele, Skeeyah, and Zusy. There are two sets of rules: one for the packed malware and one for the payload (after unpacking)

The rules were generated using 42 samples, some of which are:

    3a94750ba5dde6eef5e561721a64b24c783b0ab2
    541328c7a686bafa9e1e3132b6e2dad46935558d
    c52a21b169151b748ea12510c44421cd53e3fb4d
    8161bebbbbeaca501a0b7a45069b45604dda7fed
    94f425a8bc0687cec642e0bbf43ba218771acab5
    b1a6dd69e52bf41e9b02edf8e588b5e0962016d5
    ce6243820e58d4adb6d611073660b61a50e5f2b9
    bbc8e3d92e1703f4d4c5a560593b0b365d236b69
    099ed39b57686c5320d57ea7a6692498696c5a0e
    8eece9b6989e95127edfe70a699fdeddc9b2be99



MAGIC used the following procedure selection criteria:

   - Select clones,
   - with between 5 and 50 blocks, and
   - between 10 and 100 instructions, and
   - between 50 and 100 bytes
   - and a coverage of 80-100%

MAGIC selected 105 shared functions from the packed malware and 69 from its unpacked version (or the payload).

There are two Yara rules, both use the same selected procedures. They differ in the conditions in how the select the number of procedures that should match.
   - Version v1: Requires a subset (greater than one) of the  selected procedures to be match.
   - Version v2: Requires ANY one of the selected procedures to be present

So rule v1 is slightly more strict than v2. 

##CONTENTS##

   - CythMAGIC_birele_v1.yar: A bit stringent rule. 
   - CythMAGIC_birele_v2.yar: Most relaxed rule.
   - CythMAGIC_birele_payload_v1.yar: A bit stringent rule. 
   - CythMAGIC_birele_payload_v2.yar: Most relaxed rule. 


