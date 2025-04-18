module github.com/MuriloChianfa/srv6-blake3-pot-tlv/cmd

go 1.23.2

require github.com/aquasecurity/libbpfgo v0.6.0

replace github.com/aquasecurity/libbpfgo => ../libbpfgo

require golang.org/x/sys v0.32.0

require github.com/cilium/ebpf v0.18.0 // indirect
