// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer          *Fuzzer
	pid             int
	env             *ipc.Env
	rnd             *rand.Rand
	execOpts        *ipc.ExecOpts
	execOptsCollide *ipc.ExecOpts
	execOptsCover   *ipc.ExecOpts
	execOptsComps   *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsCollide := *fuzzer.execOpts
	execOptsCollide.Flags &= ^ipc.FlagCollectSignal
	execOptsCover := *fuzzer.execOpts
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := *fuzzer.execOpts
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:          fuzzer,
		pid:             pid,
		env:             env,
		rnd:             rnd,
		execOpts:        fuzzer.execOpts,
		execOptsCollide: &execOptsCollide,
		execOptsCover:   &execOptsCover,
		execOptsComps:   &execOptsComps,
	}
	return proc, nil
}

func (proc *Proc) updateBrfBpfStats(p *prog.Prog, info *ipc.ProgInfo) {
	if len(p.Calls) < 3 || (p.Calls[0].Meta.Name != "syz_bpf_prog_open" && p.Calls[1].Meta.Name != "syz_bpf_prog_load" && p.Calls[2].Meta.Name != "syz_bpf_prog_attach")  {
		return
	}

	var typs []int
	if info != nil {
		if info.Calls[1].Errno == 0 {
			typs = append(typs, 0)
		} else if info.Calls[1].Errno == 2 {
			typs = append(typs, 1)
		}
		if info.Calls[2].Errno == 0 {
			typs = append(typs, 2)
		} else if info.Calls[2].Errno == 3 {
			typs = append(typs, 3)
		}
	}

	for i, c := range p.Calls {
		if c.Meta.Name == "syz_bpf_prog_run_cnt" && i == len(p.Calls)-1 {
			nrun := uint64(info.Calls[i].Errno)
			log.Logf(1, "bpf nrun %v", nrun)
			if nrun == 0 {
				atomic.AddUint64(&proc.fuzzer.brfStats[BPF_BRF_NRUN][0], 1)
			}
			maxNrun := atomic.LoadUint64(&proc.fuzzer.brfStats[BPF_BRF_NRUN][1])
			if maxNrun < nrun {
				atomic.CompareAndSwapUint64(&proc.fuzzer.brfStats[BPF_BRF_NRUN][1], maxNrun, nrun)
			}
			continue
		}
	}

	if _, ok := p.Calls[0].Args[0].(*prog.PointerArg); !ok {
		return
	}
	if p.Calls[0].Args[0].(*prog.PointerArg).Res == nil {
		return
	}
	path := string(p.Calls[0].Args[0].(*prog.PointerArg).Res.(*prog.DataArg).Data())
	ps := prog.RestoreBpfSeedProg(prog.Brf, path)
	if ps == nil {
		log.Logf(3, "updateBpfStats failed to restore bpf prog")
		return
	}

	pi := stringToBrfStat(ps.ProgTypeEnum())
	if pi == 235 {
		panic(fmt.Sprintf("prog %v\n", ps.ProgTypeEnum()))
	}
	for _, typ := range typs {
		//log.Logf(3, "updateBpfStats pt")
		atomic.AddUint64(&proc.fuzzer.brfStats[pi][typ], 1)
	}
	//log.Logf(3, "updateBpfStats ht %v", len(ps.Calls))
	for _, h := range ps.Calls {
		//log.Logf(3, "updateBpfStats ht")
		hi := stringToBrfStat(h.Helper.Enum)
		if hi == 235 {
			panic(fmt.Sprintf("helper %v\n", h.Helper.Enum))
		}
		for _, typ := range typs {
		atomic.AddUint64(&proc.fuzzer.brfStats[hi][typ], 1)
		}
	}
	atomic.AddUint64(&proc.fuzzer.brfStats[BPF_BRF_NFUNC][0], uint64(len(ps.Calls)))
	maxFunc := atomic.LoadUint64(&proc.fuzzer.brfStats[BPF_BRF_NFUNC][1])
	if maxFunc < uint64(len(ps.Calls)) {
		atomic.CompareAndSwapUint64(&proc.fuzzer.brfStats[BPF_BRF_NFUNC][1], maxFunc, uint64(len(ps.Calls)))
	}
	for _, m := range ps.Maps {
		//log.Logf(3, "updateBpfStats mt")
		mi := stringToBrfStat(m.MapType)
		if mi == 235 {
			panic(fmt.Sprintf("map %v\n", m.MapType))
		}
		for _, typ := range typs {
		atomic.AddUint64(&proc.fuzzer.brfStats[mi][typ], 1)
		}
	}
	atomic.AddUint64(&proc.fuzzer.brfStats[BPF_BRF_NMAP][0], uint64(len(ps.Maps)))
	maxMap := atomic.LoadUint64(&proc.fuzzer.brfStats[BPF_BRF_NMAP][1])
	if maxMap < uint64(len(ps.Maps)) {
		atomic.CompareAndSwapUint64(&proc.fuzzer.brfStats[BPF_BRF_NMAP][1], maxMap, uint64(len(ps.Maps)))
	}
}

func (proc *Proc) updateSyzBpfStats(p *prog.Prog, info *ipc.ProgInfo) {
	resArgType := make(map[*prog.ResultArg]uint64)
	for _, c := range p.Calls {
		if c.Meta.Name != "bpf$MAP_CREATE" {
			continue
		}
		mapCreatePtr, ok := c.Args[1].(*prog.PointerArg)
		if !ok || mapCreatePtr.Res == nil {
			continue
		}

		mapCreateUnion, ok := mapCreatePtr.Res.(*prog.UnionArg)
		if !ok {
			continue
		}

		mv := mapCreateUnion.Option.(*prog.GroupArg).Inner[0].(*prog.ConstArg).Val
		resArgType[c.Ret] = mv
	}
	for i, c := range p.Calls {
		if c.Meta.Name == "syz_bpf_prog_run_cnt" && i == len(p.Calls)-1 {
			nrun := uint64(info.Calls[i].Errno)
			log.Logf(1, "bpf nrun %v", nrun)
			if nrun == 0 {
				atomic.AddUint64(&proc.fuzzer.brfStats[BPF_BRF_NRUN][0], 1)
			}
			maxNrun := atomic.LoadUint64(&proc.fuzzer.brfStats[BPF_BRF_NRUN][1])
			if maxNrun < nrun {
				atomic.CompareAndSwapUint64(&proc.fuzzer.brfStats[BPF_BRF_NRUN][1], maxNrun, nrun)
			}
			continue
		}
		if c.Meta.Name == "bpf$BPF_LINK_CREATE" || c.Meta.Name == "bpf$BPF_PROG_ATTACH" {
			typ := 0
			if info != nil && info.Calls[i].Errno == 0 {
				typ = 2
			} else {
				typ = 3
			}
			atomic.AddUint64(&proc.fuzzer.brfStats[0][typ], 1)
			continue
		}
		if c.Meta.Name == "bpf$BPF_RAW_TRACEPOINT_OPEN_UNNAMED" || c.Meta.Name == "bpf$BPF_RAW_TRACEPOINT_OPEN" {
			typ := 0
			if info != nil && info.Calls[i].Errno == 0 {
				typ = 2
			} else {
				typ = 3
			}
			atomic.AddUint64(&proc.fuzzer.brfStats[BPF_PROG_TYPE_RAW_TRACEPOINT][typ], 1)
			continue
		}
		if c.Meta.Name != "bpf$PROG_LOAD" && c.Meta.Name != "bpf$BPF_PROG_RAW_TRACEPOINT_LOAD" && c.Meta.Name != "bpf$BPF_PROG_WITH_BTFID_LOAD" {
			continue
		}
		log.Logf(1, "bpf prog load 1")

		bpfProgStructPtr, ok := c.Args[1].(*prog.PointerArg)
		if !ok || bpfProgStructPtr.Res == nil {
			continue
		}

		var bpfProgStruct *prog.GroupArg
		if c.Meta.Name == "bpf$BPF_PROG_WITH_BTFID_LOAD" {
			bpfProgWithBtfIdUnion, ok := bpfProgStructPtr.Res.(*prog.UnionArg)
			if !ok {
				continue
			}
			bpfProgStruct, ok = bpfProgWithBtfIdUnion.Option.(*prog.GroupArg)
			if !ok {
				continue
			}
		} else {
			bpfProgStruct, _ = bpfProgStructPtr.Res.(*prog.GroupArg)
		}
		pv := bpfProgStruct.Inner[0].(*prog.ConstArg).Val
		ninsn := bpfProgStruct.Inner[1].(*prog.ConstArg).Val
		log.Logf(1, "bpf pt %v ninsn %v", pv, ninsn)

		insnsPtr, ok := bpfProgStruct.Inner[2].(*prog.PointerArg)
		if !ok || insnsPtr.Res == nil {
			continue
		}

		log.Logf(1, "bpf prog load 2")
		insnsUnion, ok := insnsPtr.Res.(*prog.UnionArg)
		if !ok {
			typ := insnsPtr.Res.(*prog.GroupArg).Type()
			log.Logf(1, "%v %v", typ, typ.Name())
			continue
		}

		insnsUnionIdx := insnsUnion.Index
		log.Logf(1, "bpf insn opt %v", insnsUnionIdx)

		var rawInsnsArray *[]prog.Arg
		if insnsUnionIdx == 0 {
			rawInsnsArray = &insnsUnion.Option.(*prog.GroupArg).Inner
		} else if insnsUnionIdx == 1 {
			rawInsnsArray = &insnsUnion.Option.(*prog.GroupArg).Inner[1].(*prog.GroupArg).Inner
		}

		typ := 0
		if info != nil {
			if info.Calls[i].Errno == 0 {
				typ = 0
			} else {
				typ = 1
			}
		}

		ninsn = uint64(len(*rawInsnsArray))
		if typ == 0 {
			atomic.AddUint64(&proc.fuzzer.brfStats[BPF_BRF_NINSN][0], ninsn)
			maxNinsn := atomic.LoadUint64(&proc.fuzzer.brfStats[BPF_BRF_NINSN][1])
			if maxNinsn < ninsn {
				atomic.CompareAndSwapUint64(&proc.fuzzer.brfStats[BPF_BRF_NINSN][1], maxNinsn, ninsn)
			}
		}

		var hv []uint64
		var mv []uint64
		for _, insn := range *rawInsnsArray {
			log.Logf(1, "bpf insn type %v", insn.(*prog.UnionArg).Index)
			insnFields := insn.(*prog.UnionArg).Option.(*prog.GroupArg).Inner
			switch insn.(*prog.UnionArg).Index {
			case 0: // generic
				op := insnFields[0].(*prog.ConstArg).Val
				if op == 0x18 {//ldimm map
//					mv = insnFields[4].(*prog.ConstArg).Val
				} else if op == 0x85 {//helper call
					hv = append(hv, insnFields[4].(*prog.ConstArg).Val)
				}
//			case 1: // ldst
//				opClass := insnFields[0].(*prog.ConstArg).Val
//				opSize := insnFields[1].(*prog.ConstArg).Val
//				opMode := insnFields[2].(*prog.ConstArg).Val
//				src := insnFields[4].(*prog.ConstArg).Val
//				if (opClass|opSize|opMode) == 0x18 && src == 1 {//BPF_PSEUDO_MAP_FD
//					mv = insnFields[6].(*prog.ConstArg).Val
//				}
			case 4: // helper call
				hv = append(hv, insnFields[3].(*prog.ConstArg).Val)
//				log.Logf(1, "bpf insn call %v", h)
//				log.Logf(1, "bpf insn type %v", insn.(*prog.UnionArg).Index)
			case 9: // ldimm map
				mv = append(mv, resArgType[insnFields[4].(*prog.ResultArg).Res])
			}
		}

		//0 loaded 1 load fail 2 attached 3 attach fail


//		pe, he, me := prog.Brf.ResolveEnums(int(pv), int(hv), int(mv))
		pe := prog.Brf.ProgTypeEnumToString(int(pv))
		pi := stringToBrfStat(pe)
		if pi < 235 {
			atomic.AddUint64(&proc.fuzzer.brfStats[pi][typ], 1)
		} else {
			log.Logf(1, "debug pv %v pi %v pe %v", pv, pi, pe)
		}
		for _, h := range hv {
			he := prog.Brf.HelperEnumToString(int(pv), int(h))
			hi := stringToBrfStat(he)
			if hi < 235 {
				atomic.AddUint64(&proc.fuzzer.brfStats[hi][typ], 1)
			} else {
				log.Logf(1, "debug hv %v hi %v he %v", h, hi, he)
			}
		}
		if typ == 0 {
			atomic.AddUint64(&proc.fuzzer.brfStats[BPF_BRF_NFUNC][0], uint64(len(hv)))
			maxFunc := atomic.LoadUint64(&proc.fuzzer.brfStats[BPF_BRF_NFUNC][1])
			if maxFunc < uint64(len(hv)) {
				atomic.CompareAndSwapUint64(&proc.fuzzer.brfStats[BPF_BRF_NFUNC][1], maxFunc, uint64(len(hv)))
			}
		}
		for _, m := range mv {
			me := prog.Brf.MapTypeEnumToString(int(m))
			mi := stringToBrfStat(me)
			if mi < 235 {
				atomic.AddUint64(&proc.fuzzer.brfStats[mi][typ], 1)
			} else {
				log.Logf(1, "debug mv %v mi %v me %v", m, mi, me)
			}
		}
		if typ == 0 {
			atomic.AddUint64(&proc.fuzzer.brfStats[BPF_BRF_NMAP][0], uint64(len(mv)))
			maxMap := atomic.LoadUint64(&proc.fuzzer.brfStats[BPF_BRF_NMAP][1])
			if maxMap < uint64(len(mv)) {
				atomic.CompareAndSwapUint64(&proc.fuzzer.brfStats[BPF_BRF_NMAP][1], maxMap, uint64(len(mv)))
			}
		}
	}
}

func (proc *Proc) updateBpfStats(p *prog.Prog, info *ipc.ProgInfo) {
	if prog.Brf.IsEnabled() {
		proc.updateBrfBpfStats(p, info)
	} else {
		proc.updateSyzBpfStats(p, info)
	}
}

func (proc *Proc) loop() {
	test := false
	if test {
		for i := 0; ; i++ {
			ct := proc.fuzzer.choiceTable
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
		}
	}

	generatePeriod := 10//100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)

		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOpts, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeAndCollide(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) {
	proc.execute(execOpts, p, flags, stat)

	if proc.execOptsCollide.Flags&ipc.FlagThreaded == 0 {
		// We cannot collide syscalls without being in the threaded mode.
		return
	}
	const collideIterations = 2
	for i := 0; i < collideIterations; i++ {
		proc.executeRaw(proc.execOptsCollide, proc.randomCollide(p), StatCollide)
	}
}

func (proc *Proc) randomCollide(origP *prog.Prog) *prog.Prog {
	// Old-styl collide with a 33% probability.
	if proc.rnd.Intn(3) == 0 {
		p, err := prog.DoubleExecCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, proc.rnd)
	if proc.rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, proc.rnd)
	}
	return p
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	proc.fuzzer.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil
			}
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		proc.updateBpfStats(p, info)
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
