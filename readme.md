<h1 align="center">ftab-dump</h1>

<h5 align="center">Dumps files from 'rkos' ftab firmware images found in Apple micro-devices.</h5>
<div align="center">

| Device | Firmware Versions (ftab.bin) |
|--------|------------------------------|
| AirPods (2nd generation) | 3E751, 2C54, 1A671, 4E71, 3A283, 2D15, 6F21, 6A326, 6A321, 1A691, 2A364, 5B58, 6A300, 5E135, 5E133, 5B59, 1A673, 4C165, 4A400 |
| AirPods (3rd generation) | 4E71, 6F21, 6A326, 6A321, 6A317, 4C170, 4B66, 4B61, 5B58, 6A300, 5E135, 5E133, 5B59, 4C165 |
| AirPods Pro (1st generation) | 3E751, 2C54, 2B588, 4E71, 3A283, 2D15, 6F21, 6A326, 6A321, 4A402, 2B584, 5B58, 6A300, 5E135, 5E133, 5B59, 2D27, 4C165, 4A400 |
| AirPods Pro (2nd generation) | 5B58, 5E135, 5E133, 5A377 |
| AirPods Max | 3E756, 4E71, 7E101, 7E108, 3C39, 6F21, 6A326, 5B58, 6A300, 5E135, 7E99, 5E133, 5B59, 6F25, 6A324, 3C16, 6A325, 4C165, 4A400 |

These firmware versions use UARP Super Binaries, which require [`uarp-dump`](https://github.com/19h/uarp-dump) to extract the FTAB file from the UARP Super Binary before processing with `ftab-dump`:

| Device | UARP Versions |
|--------|------------------------------|
| AirPods (4th generation) | 7B20, 7B19, 7A304, 7E93, 8A356, 8A358 |
| AirPods Pro (2nd generation) | 7B21, 7B19, 7E93, 6A303, 7A302, 7A305, 6A305, 6B34, 6B32, 6F8, 6F7, 5B58, 5E135, 6A301, 5E133, 5A377, 8A356, 8A358, 7A294 |
| AirPods Pro (3rd generation) | 8A357, 8A358 |

</div>

<div align="center">
  <a href="https://crates.io/crates/ftab-dump">
    crates.io
  </a>
  —
  <a href="https://github.com/19h/ftab-dump">
    Github
  </a>
</div>

<br />

```shell script
$ cargo install ftab-dump
$ ftab-dump -v ftab.bin -o ftab_dump
```

#### Special thanks

- B1N4R1 B01 (<a href="http://twitter.com/b1n4r1b01">Twitter</a> - <a href="https://github.com/b1n4r1b01">Github</a>)
- <a href="https://github.com/libimobiledevice/idevicerestore/blob/8207daaa2ac3cb3a5107aae6aefee8ecbe39b6d4/src/ftab.h#L31-L57">Nikias Bassen of the idevicerestore project</a>

#### Notes

If you intend to analyze `rkos` files, note that the AirPods Pro 1, 2 and 3 use an Arm Cortex-M4 32-bit RISC CPU with VFPv4 and ThumbV2 instructions using the ARMv7-M architecture with a little endian byte sex.

#### License

~~ MIT License ~~

Copyright (c) 2020 - 2025 Kenan Sulayman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
