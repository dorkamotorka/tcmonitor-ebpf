package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf tcmonitor tcmonitor.c

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/pflag"
)

var (
	tcKeys = map[string]uint32{
		"TC_ACT_OK":        0,
		"TC_ACT_RECLASSIFY": 1,
		"TC_ACT_SHOT":       2,
		"TC_ACT_PIPE":       3,
		"TC_ACT_STOLEN":     4,
		"TC_ACT_QUEUED":     5,
		"TC_ACT_REPEAT":     6,
		"TC_ACT_REDIRECT":   7,
		"TC_ACT_TRAP":       8,
	}
	tcKeyOrder = []string{"TC_ACT_OK", "TC_ACT_RECLASSIFY", "TC_ACT_SHOT", "TC_ACT_PIPE", "TC_ACT_STOLEN", "TC_ACT_QUEUED", "TC_ACT_REPEAT", "TC_ACT_REDIRECT", "TC_ACT_TRAP"}
)

func getFuncName(prog *ebpf.Program) (string, error) {
	info, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("failed to get program info: %w", err)
	}

	if info.Type != ebpf.SchedCLS && info.Type != ebpf.SchedACT {
		return "", fmt.Errorf("program is not a TC program")
	}

	if _, ok := info.BTFID(); !ok {
		return "", fmt.Errorf("program does not have BTF ID")
	}

	insns, err := info.Instructions()
	if err != nil {
		return "", fmt.Errorf("failed to get program instructions: %w", err)
	}

	for _, insn := range insns {
		if sym := insn.Symbol(); sym != "" {
			return sym, nil
		}
	}
	return "", fmt.Errorf("no entry function found in program")
}

func lookupAndPrintStats(ebpfMap *ebpf.Map, prevValues map[string]uint64, prevTime *time.Time) {
	fmt.Println("\nTC Actions:")
	now := time.Now()
 	deltaTime := now.Sub(*prevTime).Seconds()
 	if deltaTime == 0 {
 		return // Avoid division by zero
 	}
	for _, action := range tcKeyOrder {
		key := tcKeys[action]
		var value uint64
		if err := ebpfMap.Lookup(&key, &value); err != nil {
			log.Printf("Error looking up %s: %v", action, err)
			continue
		}
		prev := prevValues[action]
 		prevValues[action] = value
 		rate := float64(value-prev) / deltaTime
 		fmt.Printf("%s: %d (Rate: %.2f/s)\n", action, value, rate)
	}
	*prevTime = now
}

func main() {
	var tcProgID int
	pflag.IntVarP(&tcProgID, "tc-program-id", "i", 0, "TC program ID to trace")
	pflag.Parse()

	if tcProgID == 0 {
		log.Fatal("You need to specify a valid TC Program ID.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	spec, err := loadTcmonitor()
	if err != nil {
		log.Fatalf("Failed to load tcmonitor BPF spec: %v", err)
	}

	tcProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(tcProgID))
	if err != nil {
		log.Fatalf("Failed to load TC program ID %d: %v", tcProgID, err)
	}
	defer tcProg.Close()

	tcFuncName, err := getFuncName(tcProg)
	if err != nil {
		log.Fatalf("Failed to get function name: %v", err)
	}

	tcFexit := spec.Programs["fexit_tc"]
	tcFexit.AttachTarget = tcProg
	tcFexit.AttachTo = tcFuncName

	var obj tcmonitorObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		if ve := new(ebpf.VerifierError); errors.As(err, &ve) {
			log.Fatalf("Failed to load BPF object: %v\nVerifier log:\n%v", err, ve)
		}
		log.Fatalf("Failed to load BPF object: %v", err)
	}
	defer obj.Close()

	tcfexit, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitTc,
	})
	if err != nil {
		log.Fatalf("Failed to attach fexit program: %v", err)
	}
	defer tcfexit.Close()

	fmt.Printf("Tracing TC Program with ID %d...\n", tcProgID)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

 	prevValues := make(map[string]uint64)
 	prevTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nExiting...")
			return
		case <-ticker.C:
			fmt.Print("\033[H\033[J") // Clear screen
			lookupAndPrintStats(obj.TcActionCountMap, prevValues, &prevTime)
		}
	}
}
