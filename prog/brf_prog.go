package prog

import (
	"encoding/gob"
	"fmt"
	"os"
	"time"
)

type BpfProg struct {
	BasePath     string
	UseTestSrc   bool

	pt          *BpfProgType
	TypeEnum    BpfProgTypeEnum
	VarId       int
	Maps        []*BpfMap
	Calls       []*BpfCall
	Structs     []*StructDef
	Externs     map[string]string
	CtxVars     map[string]string
	CtxTypes    map[string]string
	RetVal      int
	SecStr      string
	Sec         SecDef
}

type BrfGenProgOpt struct {
	genProgAttempt   int
	useTestSrc       bool
	basePath	 string
}

func newBpfProg(r *randGen, opt BrfGenProgOpt) *BpfProg {
	p := &BpfProg {}

	if (opt.useTestSrc) {
		p.BasePath = opt.basePath + "/test_prog"
		p.UseTestSrc = true
	} else {
		p.BasePath = fmt.Sprintf("%v/prog_%x", opt.basePath, time.Now().UnixNano())
	}

	return p
}

func (p *BpfProg) writeCSource() error {
	var progSrc string

	if (p.UseTestSrc) {
		progSrc = testSrc
	} else {
		progSrc = p.genCSource()
	}

	f, err := os.Create(p.BasePath + ".c")
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(progSrc)
	return err
}

func (p *BpfProg) writeGob() error {
	f, err := os.Create(p.BasePath + ".gob")
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewEncoder(f).Encode(p)
}

func (p *BpfProg) readGob(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return gob.NewDecoder(file).Decode(p)
}


var testSrc = `
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define DEFINE_BPF_MAP(the_map, TypeOfMap, MapFlags, TypeOfKey, TypeOfValue, MaxEntries) \
        struct {                                                        \
            __uint(type, TypeOfMap);                                    \
            __uint(map_flags, (MapFlags));                              \
            __uint(max_entries, (MaxEntries));                          \
            __type(key, TypeOfKey);                                     \
            __type(value, TypeOfValue);                                 \
        } the_map SEC(".maps");

DEFINE_BPF_MAP(array_map, BPF_MAP_TYPE_ARRAY, 0, int, int, 1);

SEC("cgroup_skb/egress")
int func(struct __sk_buff *ctx)
{
	int *value, key = 0;
	value = bpf_map_lookup_elem(&array_map, &key);
	return 0;
}
`
