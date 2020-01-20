<h1 align="center">ftab-dump</h1>

<h5 align="center">Dumps files from 'rkos' ftab firmware images found in Apple micro-devices.</h5>
<h5 align="center">
- AirPods1,1 w/ B188AP (AirPod 1st generation)<br/>
- AirPods2,1 w/ B288AP (AirPod 2nd generation)<br/>
- iProd8,1 w/ B298AP (AirPod Pro)<br/>
- and probably future devices
</h5>

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

`cargo` requires a rust installation.

#### License

~~ MIT License ~~

Copyright (c) 2020 Kenan Sulayman

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
