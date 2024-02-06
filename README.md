# snapshot: A WinDbg extension written in Rust that generates a snapshot for fuzzing
![Builds](https://github.com/0vercl0k/snapshot/workflows/Builds/badge.svg)

<p align='center'>
<img src='pics/snapshot.gif'>
</p>

snapshot is a WinDbg extension written in Rust that dumps both the state of a CPU and the physical memory of a running VM. This snapshot is meant to be used by snapshot-based fuzzers and more particularly by [wtf](https://github.com/0vercl0k/wtf).

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
