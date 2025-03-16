# tcmonitor-ebpf

Repository for monitoring TC actions using eBPF. In other words tracing eBPF with eBPF.

While working on various eBPF projects, I often needed to trace TC eBPF return codes. And not just that, if there were multiple TC program I wanted to figure what actions does a specific one infers on the received traffic. 

tcmonitor-ebpf attaches to the specified TC program (using the `-i` or `--tc-program-id` flag) and monitors all possible actions an TC program can enforce on packets.

## How to use it

First, using `bpftool` find the TC program ID:
```
$ sudo bpftool prog
```

Then just run the `tcmonitor-ebpf`:
```
$ sudo ./tcmonitor-ebpf -i <tc-program-id>
```
~      
