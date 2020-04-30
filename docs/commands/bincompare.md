## Command bincompare

The `bincompare` command will compare a provided binary file with process memory in order to find differences between the two.

`bincompare` require options:

* `-f` (for `file`) - the full path of binary file to be compared.
* `-a` (for `address`) - the memory address to be compared with the file data.

You can use the `bytearray` command to generate the binary file.

Example without badchars:
```
gef>  bincompare -f bytearray.bin -a 0x56557008
[+] Comparison result:
    +-----------------------------------------------+
 00 |00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f| file
    |                                               | memory
 10 |10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f| file
    |                                               | memory
 20 |20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f| file
    |                                               | memory
 30 |30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f| file
    |                                               | memory
 40 |40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f| file
    |                                               | memory
 50 |50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f| file
    |                                               | memory
 60 |60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f| file
    |                                               | memory
 70 |70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f| file
    |                                               | memory
 80 |80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f| file
    |                                               | memory
 90 |90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f| file
    |                                               | memory
 a0 |a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af| file
    |                                               | memory
 b0 |b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf| file
    |                                               | memory
 c0 |c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf| file
    |                                               | memory
 d0 |d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df| file
    |                                               | memory
 e0 |e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef| file
    |                                               | memory
 f0 |f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff| file
    |                                               | memory
    +-----------------------------------------------+

[+] No badchars found!
```

Example with badchars and no truncateed buffer:
```
gef>  bincompare -f bytearray.bin -a 0x56557008
[+] Comparison result:
    +-----------------------------------------------+
 00 |00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f| file
    |               10                              | memory
 10 |10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f| file
    |                                             10| memory
 20 |20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f| file
    |                                               | memory
 30 |30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f| file
    |                                             2f| memory
 40 |40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f| file
    |                                               | memory
 50 |50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f| file
    |                                               | memory
 60 |60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f| file
    |                                               | memory
 70 |70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f| file
    |                                               | memory
 80 |80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f| file
    |                                               | memory
 90 |90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f| file
    |                                               | memory
 a0 |a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af| file
    |                                               | memory
 b0 |b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf| file
    |                                               | memory
 c0 |c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf| file
    |                                               | memory
 d0 |d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df| file
    |                                               | memory
 e0 |e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef| file
    |                                               | memory
 f0 |f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff| file
    |                                               | memory
    +-----------------------------------------------+

[+] Badchars found: 05, 1f, 3f
```

Example with badchars and truncated buffer:
```
gef>  bincompare -f bytearray.bin -a 0x56557008
[+] Comparison result:
    +-----------------------------------------------+
 00 |00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f| file
    |               10                              | memory
 10 |10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f| file
    |                                             10| memory
 20 |20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f| file
    |                                               | memory
 30 |30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f| file
    |                                             2f| memory
 40 |40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f| file
    |      00 00 01 1b 03 3b 38 00 00 00 06 00 00 00| memory
 50 |50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f| file
    |d4 ef ff ff 80 00 00 00 f4 ef ff ff a4 00 00 00| memory
 60 |60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f| file
    |04 f0 ff ff 54 00 00 00 74 f1 ff ff b8 00 00 00| memory
 70 |70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f| file
    |d4 f1 ff ff 04 01 00 00 d5 f1 ff ff 18 01 00 00| memory
 80 |80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f| file
    |14 00 00 00 00 00 00 00 01 7a 52 00 01 7c 08 01| memory
 90 |90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f| file
    |1b 0c 04 04 88 01 07 08 10 00 00 00 1c 00 00 00| memory
 a0 |a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af| file
    |a8 ef ff ff 36 00 00 00 00 00 00 00 14 00 00 00| memory
 b0 |b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf| file
    |00 00 00 00 01 7a 52 00 01 7c 08 01 1b 0c 04 04| memory
 c0 |c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf| file
    |88 01 00 00 20 00 00 00 1c 00 00 00 4c ef ff ff| memory
 d0 |d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df| file
    |20 00 00 00 00 0e 08 46 0e 0c 4a 0f 0b 74 04 78| memory
 e0 |e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef| file
    |00 3f 1a 3b 2a 32 24 22 10 00 00 00 40 00 00 00| memory
 f0 |f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff| file
    |48 ef ff ff 08 00 00 00 00 00 00 00 48 00 00 00| memory
    +-----------------------------------------------+

[+] Corruption after 66 bytes
[+] Badchars found: 05, 1f, 3f, 42, 43, 44, 45, 46, 47, 48, 49, 4a, 4b, 4c, 4d, 4e, 4f, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 5a, 5b, 5c, 5d, 5e, 5f, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 6a, 6b, 6c, 6d, 6e, 6f, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 7a, 7b, 7c, 7d, 7e, 7f, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 8a, 8b, 8c, 8d, 8e, 8f, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 9a, 9b, 9c, 9d, 9e, 9f, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, aa, ab, ac, ad, ae, af, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, ba, bb, bc, bd, be, bf, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, ca, cb, cc, cd, ce, cf, d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, da, db, dc, dd, de, df, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, ea, eb, ec, ed, ee, ef, f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, fa, fb, fc, fd, fe, ff
```
