**WannaCry (cluster 5) - YARA rules generated by malware genomic analysis**

The rules were generated using a cluster of the following 6 samples.

    15e3f4f2412838cea63213ab0e27d089983cc2fd
    82d3d0dc267b2d85e5a33e3316bfbf7480045420
    426ffd1415e6c78d6376584c83c10b6dd137a16b
    7408c7bec49d8a603ce3c2499564991c3db4bec7
    f1ee3d2caa60e2174fdc69c3c5c8d3d1aefc1b80
    577ddc3ee7b8459f85daf90d6af4649651ab7449

MAGIC used the following procedure selection criteria:

   - Select clones,
   - with between 5 and 50 blocks, and
   - between 10 and 100 instructions, and
   - between 50 and 100 bytes
   - and a coverage of 80-100%

MAGIC selected 54 shared functions that matched this criteria.


There are two Yara rules, both use the same selected procedures. They differ in the conditions in how the select the number of procedures that should match.
   - Version v1: Requires a subset (greater than one) of the  selected procedures to be match.
   - Version v2: Requires ANY one of the selected procedures to be present

So rule v1 is slightly more strict than v2. 

##CONTENTS##

   - CythMAGIC_wannacry5_v1.yar: A bit stringent rule. 
   - CythMAGIC_wannacry5_v2.yar: Most relaxed rule.
   


