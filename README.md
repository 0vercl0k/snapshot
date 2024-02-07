<div align='center'>
  <h1><code>snapshot</code></h1>
  <p>
    <strong>A Rust WinDbg extension that takes a snapshot of a running VM.</strong>
  </p>
  <p>
    <img src='https://github.com/0vercl0k/snapshot/workflows/Builds/badge.svg'/>
  </p>
  <p>
    <img src='pics/snapshot.gif' />
  </p>
</div>

`snapshot` is a WinDbg extension written in Rust that dumps both the state of a CPU (GPRs, relevant MSRs, FPU state, segments, etc.) and the physical memory of a running VM (via a memory crash-dump). This snapshot is meant to be used by snapshot-based fuzzers and more particularly by [wtf](https://github.com/0vercl0k/wtf).

This code base is also meant to show case how to write a WinDbg extension in Rust 🦀.

## Building
You can build the extension with the below:
```text
c:\> git clone https://github.com/0vercl0k/snapshot.git
c:\> cd snapshot
c:\snapshot> cargo build --release
```

If you would rather grab a pre-built extension, grab one on the [releases](https://github.com/0vercl0k/snapshot/releases) page.

## Grabbing a snapshot
Once you have the extension downloaded / compiled, you can load it in WinDbg with the below:
```text
kd> .load \path\to\snapshot\target\release\snapshot.dll
```

Generate a full-kernel snapshot in the `c:\foo` directory with the below:
```text
kd> !snapshot c:\foo
[snapshot] Dumping the CPU state into c:\foo\state.19041.1.amd64fre.vb_release.191206-1406.20240205_173527\regs.json..
[snapshot] Dumping the memory state into c:\foo\state.19041.1.amd64fre.vb_release.191206-1406.20240205_173527\mem.dmp..
Creating c:\\foo\\state.19041.1.amd64fre.vb_release.191206-1406.20240205_173527\\mem.dmp - Full memory range dump
0% written.
5% written. 1 min 12 sec remaining.
10% written. 1 min 4 sec remaining.
[...]
90% written. 6 sec remaining.
95% written. 3 sec remaining.
Wrote 4.0 GB in 1 min 11 sec.
The average transfer rate was 57.7 MB/s.
Dump successfully written
[snapshot] Done!
```

There is also `!snapshot_active_kernel` if you would prefer to grab an active kernel crash-dump.
