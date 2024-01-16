package prog

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type BpfRuntimeFuzzer struct {
	isEnabled     bool
}

func NewBpfRuntimeFuzzer(enable bool) *BpfRuntimeFuzzer {
	brf := new(BpfRuntimeFuzzer)
	brf.isEnabled = true

	return brf
}

func (brf *BpfRuntimeFuzzer) IsEnabled() bool {
	return brf.isEnabled
}

func (brf *BpfRuntimeFuzzer) GenPrologue(r *randGen, s *state, prog *Prog) {
	var p *BpfProg

	if !brf.isEnabled {
		return
	}

	p = brf.genSeedBpfProg(r)
	_ = p
}

func (brf *BpfRuntimeFuzzer) genSeedBpfProg(r *randGen) *BpfProg {
	var opt BrfGenProgOpt
	var p *BpfProg
	var ok bool

	opt.useTestSrc = true
	opt.genProgAttempt = 20

	for i := 0; i < opt.genProgAttempt; i++ {
		if p, ok = brf.genBpfProg(r, opt); !ok {
			continue
		}

		if err := p.writeCSource(); err != nil {
			fmt.Printf("failed to write bpf program c source: %v\n", err)
			return nil
		}

		if err := p.writeGob(); err != nil {
			fmt.Printf("failed to serialize bpf program: %v\n", err)
			return nil
		}

		if err := brf.compileBpfProg(p); err != nil {
			fmt.Printf("failed to compile bpf program: %v\n", err)
			continue
		}
		return p
	}
	return nil
}

func (brf *BpfRuntimeFuzzer) genBpfProg(r *randGen, opt BrfGenProgOpt) (*BpfProg, bool) {
	p := newBpfProg(r, opt)

	return p, true
}

func (brf *BpfRuntimeFuzzer) compileBpfProg(p *BpfProg) error {
	var timeout time.Duration = 10000000000
	cmd := exec.Command("clang-16", "-g", "-D__TARGET_ARCH_x86", "-mlittle-endian",
		"-idirafter", "/usr/local/include",
		"-idirafter", "/usr/local/llvm/include",
		"-idirafter", "/usr/include/x86_64-linux-gnu",
		"-idirafter", "/usr/include",
		"-Wno-compare-distinct-pointer-types",
		"-Wno-int-conversion",
		"-O2", "-target", "bpf", "-mcpu=v3",
		"-c", p.BasePath + ".c",
		"-o", p.BasePath + ".o")

	_, err := osutil.Run(timeout, cmd)
	return err
}
