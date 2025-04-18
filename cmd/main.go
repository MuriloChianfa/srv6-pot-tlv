package main

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/cilium/ebpf"
)

const defaultMapPath = "/sys/fs/bpf/seg6_pot_keys"

//go:embed build/seg6_pot_tlv.o
var bpfObj []byte

func main() {
	loadIface := flag.String("load", "", "Install and Attach eBPF programs to <iface>")
	sidStr := flag.String("sid", "", "IPv6 SID (e.g. 2001:db8::1)")
	keyHex := flag.String("key", "", "32-byte key as 64 hex digits")
	flag.Parse()

	switch {
	case *loadIface != "":
		if err := loadPrograms(*loadIface); err != nil {
			log.Fatalf("[-] load failed: %v", err)
		}
		fmt.Printf("[+] Loaded TC & XDP programs on %s\n", *loadIface)
		return

	case *sidStr != "" && *keyHex != "":
		if err := updateMap(*sidStr, *keyHex); err != nil {
			log.Fatalf("[-] map update failed: %v", err)
		}
		fmt.Printf("[+] Inserted SID %s → key %s into %s\n", *sidStr, *keyHex, defaultMapPath)
		return

	default:
		flag.Usage()
		os.Exit(1)
	}
}

func updateMap(sidStr, keyHex string) error {
	ip := net.ParseIP(sidStr)
	if ip == nil || ip.To16() == nil {
		return fmt.Errorf("invalid IPv6 SID: %q", sidStr)
	}
	sid := ip.To16()

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("hex decode key: %w", err)
	}
	if len(keyBytes) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(keyBytes))
	}

	m, err := ebpf.LoadPinnedMap(defaultMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("open pinned map: %w", err)
	}
	defer m.Close()

	if err := m.Update(sid, keyBytes, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("map.Update: %w", err)
	}
	return nil
}

func loadPrograms(iface string) error {
	// load & parse our embedded BPF object
	module, err := bpf.NewModuleFromBuffer(bpfObj, "seg6_pot_tlv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "BPF new module: %v\n", err)
		os.Exit(1)
	}
	defer module.Close()

	if err := module.BPFLoadObject(); err != nil {
		fmt.Fprintf(os.Stderr, "BPF load object: %v\n", err)
		os.Exit(1)
	}

	xdpProg, err := module.GetProgram("seg6_pot_tlv_d")
	if err != nil || xdpProg == nil {
		return fmt.Errorf("get XDP program: %w", err)
	}
	xdpLink, err := xdpProg.AttachXDP(iface)
	if err != nil {
		return fmt.Errorf("attach XDP ingress: %w", err)
	}
	defer xdpLink.Destroy()

	// initialize a TC hook, point it at our interface, and set egress
	hook := module.TcHookInit()
	defer hook.Destroy()

	if err := hook.SetInterfaceByName(iface); err != nil {
		fmt.Fprintf(os.Stderr, "set interface: %v\n", err)
		os.Exit(1)
	}
	hook.SetAttachPoint(bpf.BPFTcEgress)
	if err := hook.Create(); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("tc hook create: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[+] tc hook already existed, re-using\n")
	}

	tcProg, err := module.GetProgram("seg6_pot_tlv")
	if err != nil || tcProg == nil {
		fmt.Fprintf(os.Stderr, "get program: %v\n", err)
		os.Exit(1)
	}

	// prepare attach options
	var opts bpf.TcOpts
	opts.ProgFd = int(tcProg.GetFd())
	opts.Handle = 1
	opts.Priority = 1

	// attach it
	if err := hook.Attach(&opts); err != nil {
		fmt.Fprintf(os.Stderr, "tc attach: %v\n", err)
		os.Exit(1)
	}
	defer hook.Detach(&opts)

	fmt.Printf("TC egress program attached on %s — press Ctrl-C to exit\n", iface)

	// wait for Ctrl‑C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Detaching and exiting…")

	return nil
}
