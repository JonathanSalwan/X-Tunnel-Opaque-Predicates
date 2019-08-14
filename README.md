These opaque predicates come from the X-Tunnel (99B454262DC26B081600E844371982A49D334E5E) malware.
They were automatically extracted using Triton within an IDA plugin and classified in three groups
of form and one group without any particular form.

* Group 1: (x * x * 7) - 1 != y * y          (3197, 44.35%)
* Group 2: 2 / ((x * x) + 1) != (y * y) + 3  (3873, 53.72%)
* Group 3: x - x = 0                         (108,  01.05%)
* Unclassified                               (31,   00.43%)
