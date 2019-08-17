IDA+Triton plugin in order to extract opaque predicates where their computation is local to a single basic
block using a Forward-Bounded DSE.

We tested the plugin on the X-Tunnel (99B454262DC26B081600E844371982A49D334E5E) malware in order to extract
all its opaque predicates (some stats: 50,302 conditions analyzed in 23 minutes and 7209 opaque predicates
found). We can see that most of OP are mainly constructed in three forms but we also found 31 others ones
without any particular form. Repartition of opaque predicates by form is detailed below:

```
Group 1: (x * x * 7) - 1 != y * y          (3197, 44.35%)
Group 2: 2 / ((x * x) + 1) != (y * y) + 3  (3873, 53.72%)
Group 3: x - x = 0                         (108,  01.05%)
Unclassified                               (31,   00.43%)
```

Files `.po` contain all OP found and extracted (one OP per line and each SymVar is a 8 bits symbolic variable).

Related work: [Backward-Bounded DSE: Targeting Infeasibility Questions on Obfuscated Codes](http://sebastien.bardin.free.fr/2017-sp.pdf)
