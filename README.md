# nft_inspect

Utility that tracks nf_tables DROP verdicts (actually all that are not ACCEPT) through the different namespaces, and displays the ethernet adapter properties. The objective is to be able to identify what adapter drops/doesn't accept a packet, useful in a multi-adapter/multi-namespace environment.

## Note

The nf_tables module must be loaded for the kretprobe registration to succeed. Otherwise, it will fail with return code -2;

## Output

The output can be grabbed via dmesg and will look something like this

```  
[Sun Jan  7 17:27:34 2024] ipt_do_table(filter) - devin=(null)/0, devout=eth0/2, saddr=0xa010002, daddr=0xa010001, proto=6, spt=0xb986, dpt=0x1f90, verdict=0
```

- devin: ingress device
- devout: egress device
- saddr: source IP address in little-endian (hex)
- daddr: destination IP address in little-endian (hex)
- proto: "tcp" or "udp"
- spt: source TCP/UDP port in little-endian (hex)
- dpt: destination TCP/UDP port in little-endian (hex)
- retval: netfilter verdict NF_* which values/code mappings can be found in uapi/linux/netfilter.h
