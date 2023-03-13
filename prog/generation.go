// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)

	var progFd *ResultArg
	var ps *BpfProgState
	if Brf.isEnabled {
		fmt.Printf("Generate\n")
		ps = Brf.GenBpfSeedProg(r)

		c0 := r.generateBpfProgOpenCall(s, ps)
		s.analyze(c0)
		p.Calls = append(p.Calls, c0)

		c1 := r.generateBpfProgLoadCall(s, ps)
		s.analyze(c1)
		p.Calls = append(p.Calls, c1)
		progFd = c1.Ret

		c2 := r.generateBpfProgAttachCall(s, ps, c1.Ret)
		s.analyze(c2)
		p.Calls = append(p.Calls, c2)

		c3 := r.generateBpfProgTestRunCall(s, ps, c1.Ret)
		s.analyze(c3)
		p.Calls = append(p.Calls, c3)
	}

	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}

	toAppend := true
	var toBeRemoved []int
	for i, c := range p.Calls {
		if c.Meta.Name == "syz_bpf_prog_run_cnt" {
			if i != len(p.Calls)-1 {
				toBeRemoved = append(toBeRemoved, i)
			} else {
				toAppend = false
			}
		}
		if progFd == nil && (c.Meta.Name == "syz_bpf_prog_load" || c.Meta.Name == "bpf$PROG_LOAD" || c.Meta.Name == "bpf$BPF_PROG_RAW_TRACEPOINT_LOAD") {
			progFd = c.Ret
		}
	}
	removed := 0
	for _, i := range toBeRemoved {
		p.RemoveCall(i-removed)
		removed += 1
	}
	if progFd != nil && toAppend {
		if len(p.Calls) == ncalls {
			p.RemoveCall(ncalls - 1)
		}
		c := r.generateBpfProgRunCntCall(s, progFd)
		s.analyze(c)
		p.Calls = append(p.Calls, c)
	}

	p.sanitizeFix()
	p.debugValidate()
	return p
}
