package prog

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type BpfRuntimeFuzzer struct {
	isEnabled     bool
	workDir       string
}

func NewBpfRuntimeFuzzer(enable bool) *BpfRuntimeFuzzer {
	brf := new(BpfRuntimeFuzzer)

	if (!enable) {
		return brf
	}

	brf.workDir = "/mnt/brf_work_dir"
	err := mountBrfWorkDir(brf.workDir)
	if (err != nil) {
		return brf
	}

	brf.isEnabled = true

	return brf
}

func mountBrfWorkDir(dir string) error {
	var timeout time.Duration = 10000000000

	err := os.Mkdir(dir, os.ModeDir)
	if err != nil {
		fmt.Printf("failed to create brf work dir: %v\n", err)
		return err
	}

	args := []string{"-t", "9p", "-o", "trans=virtio,version=9p2000.L", "brf", dir}
	_, err = osutil.RunCmd(timeout, "", "mount", args...)
	if err != nil {
		fmt.Printf("failed to mount brf work dir: %v\n", err)
		return err
	}
	return nil
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

	c0 := genBpfProgOpenCall(r, s, p)
	s.analyze(c0)
	prog.Calls = append(prog.Calls, c0)

	c1 := genBpfProgLoadCall(r, s, p)
	s.analyze(c1)
	prog.Calls = append(prog.Calls, c1)

	c2 := genBpfProgAttachCall(r, s, p)
	s.analyze(c2)
	prog.Calls = append(prog.Calls, c2)

	c3 := genBpfProgTestRunCall(r, s, p, c1.Ret)
	s.analyze(c3)
	prog.Calls = append(prog.Calls, c3)
}

func genBpfProgOpenCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_open"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgLoadCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_load"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)
	args[1], _ = r.generateArg(s, meta.Args[1].Type, meta.Args[1].Dir(DirIn))

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgAttachCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_attach"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgTestRunCall(r *randGen, s *state, p *BpfProg, fd *ResultArg) *Call {
	meta := r.target.SyscallMap["bpf$BPF_PROG_TEST_RUN"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	cmdArg := meta.Args[0]
	args[0], _ = r.generateArg(s, cmdArg.Type, cmdArg.Dir(DirIn))

	testProgArg := meta.Args[1]
	testProgPtr := testProgArg.Type.(*PtrType)
	testProgStruct := testProgPtr.Elem.(*StructType)
	testProgStructDir := testProgPtr.ElemDir

	testProgStructFields := make([]Arg, len(testProgStruct.Fields))
	for i, field := range testProgStruct.Fields {
		if i == 0 {
			resArg := field
			resType := resArg.Type.(*ResourceType)
			testProgStructFields[i] = MakeResultArg(resType, resArg.Dir(DirIn), fd, 0)
		} else {
			testProgStructFields[i], _ = r.generateArg(s, field.Type, field.Dir(DirIn))
		}
	}

	testProgStructArg := MakeGroupArg(testProgStruct, testProgStructDir, testProgStructFields)
	args[1] = r.allocAddr(s, testProgArg.Type, testProgArg.Dir(DirIn), testProgStructArg.Size(), testProgStructArg)

	lenArg := meta.Args[2]
	args[2], _ = r.generateArg(s, lenArg.Type, lenArg.Dir(DirIn))

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func (brf *BpfRuntimeFuzzer) genSeedBpfProg(r *randGen) *BpfProg {
	var opt BrfGenProgOpt
	var p *BpfProg
	var ok bool

	opt.useTestSrc = true
	opt.genProgAttempt = 20
	opt.basePath = brf.workDir

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
	cmd.Dir = brf.workDir

	_, err := osutil.Run(timeout, cmd)
	return err
}
