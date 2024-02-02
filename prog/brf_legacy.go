package prog

import (
	"bytes"
	"fmt"
	"time"
	"strings"
)

type SecDefGenFunc func(r *randGen) (string, *StructDef)

type SecDef struct {
	Sec        string
	SecDefGen  SecDefGenFunc
	Sleepable  bool
}

type BpfProgTypeEnum int

type BpfProgType struct {
	Name       string
	User       string
	Kern       string
	Enum       BpfProgTypeEnum
	SecDefs    []SecDef
	FuncProtos []string
	Helpers    []*BpfHelper
	ctxAccess  *BpfCtxAccess
}

func (pt *BpfProgType) getHelper(helperEnum BpfHelperEnum) *BpfHelper {
	for _, helper := range pt.Helpers {
		if helper.Enum == helperEnum {
			return helper
		}
	}
	return nil
}

func (pt *BpfProgType) getHelpers(helperEnums []BpfHelperEnum) []*BpfHelper {
	var helpers []*BpfHelper
	for _, helper := range pt.Helpers {
		for _, enum := range helperEnums {
			if helper.Enum == enum {
				helpers = append(helpers, helper)
			}
		}
	}
	return helpers
}

type BpfHelperEnum int

type BpfHelper struct {
	Uname      string
	Enum       BpfHelperEnum
	Impl       string
	Proto      string
	Args       []string
	ArgBtfIds  []string
	Ret        string
	RetBtfId   string
	GplOnly    bool
	PktAccess  bool
}

type BpfMapType struct {
	Name        string
	ManFlags    [][]string
	OptFlags    [][]string
	KeySize     []int
	ValSize     []int
	MaxEntries  int
}

type BpfMap struct {
	Name       string
	Type       string
	Flags      []string
	Key        *StructDef
	Val        *StructDef
	MaxEntries int64
	InnerMap   *BpfMap
}

func (m *BpfMap) getFlag(f string) int {
	for i, flag := range m.Flags {
		if flag == f {
			return i
		}
	}
	return -1
}

func (m *BpfMap) addFlag(flag string) {
	if f := m.getFlag(flag); f == -1 {
		m.Flags = append(m.Flags, flag)
	}
}

func (m *BpfMap) removeFlag(flag string) {
	if f := m.getFlag(flag); f != -1 {
		m.Flags = append(m.Flags[0:f], m.Flags[f+1:]...)
	}
}

func (m *BpfMap) FlagsStr() string {
	flags := "0"
	for _, f := range m.Flags {
		flags = flags + " | " + f
	}
	return flags
}

func (m *BpfMap) String() string {
	s := new(bytes.Buffer)

        fmt.Fprintf(s, "struct {\n")
        fmt.Fprintf(s, "    __uint(type, %v);\n", m.Type)
        fmt.Fprintf(s, "    __uint(map_flags, %v);\n", m.FlagsStr())
        fmt.Fprintf(s, "    __uint(max_entries, %v);\n", m.MaxEntries)
	if m.Key != nil {
		fmt.Fprintf(s, "    __type(key, %v);\n", m.Key.Name)
	}
	if m.Val != nil {
		fmt.Fprintf(s, "    __type(value, %v);\n", m.Val.Name)
	}
	if m.InnerMap != nil {
		fmt.Fprintf(s, "} %v SEC(\".maps\") = { .values = {&%v}, };\n", m.Name, m.InnerMap.Name)
	} else {
		fmt.Fprintf(s, "} %v SEC(\".maps\");\n", m.Name)
	}

	return s.String()
}

type ArgHint int32

const (
	HintGenSpinlock = iota
	HintGenTimer
	HintGenConstStr
	HintGenXdpSockMap
	HintGenSockMap
)

type BpfCallGenHint struct {
	ArgHints        map[ArgHint]bool
	RetAccessSize   int     // return value will be accessed with the size
	IsRetAccessRaw  bool    // return value is used for raw memory access
	PreferredMap    *BpfMap
}

func newBpfCallGenHint(m *BpfMap) *BpfCallGenHint {
	hint := &BpfCallGenHint {
		ArgHints: make(map[ArgHint]bool),
		RetAccessSize: 0,
		IsRetAccessRaw: false,
		PreferredMap: m,
	}
	return hint
}

type BpfArg struct {
	Name            string
	ArgType         string
	Prepare         string
	CanBeNull       bool
	IsNotNull       bool
	Umin            int64
	Umax            int64
	IsPktAccess     bool
	IsPktMetaAccess bool
	AccessSize      int
}

func NewBpfArg(helper *BpfHelper, arg int) *BpfArg {
	newArg := &BpfArg{
		ArgType: helper.Args[arg],
		CanBeNull: true,
		Umin: int64(-1),
		Umax: int64(-1),
	}

	argType := newArg.ArgType
	//XXX need to review the constraints
	if argType[0:9] == "ARG_CONST" {
		if argType == "ARG_CONST_SIZE" {
			newArg.Umin = int64(0)
			newArg.Umax = int64(1 << 29)
		} else if argType == "ARG_CONST_SIZE_OR_ZERO" {
			newArg.Umax = int64(1 << 29)
		}
		//"ARG_CONST_ALLOC_SIZE_OR_ZERO"
	} else if argType[len(argType)-7:len(argType)] != "OR_NULL" || argType == "ARG_PTR_TO_MAP_VALUE_OR_NULL"{ //XXX investigate 5065 to how may_be_null work/the difference between ARG_PTR_TO_MAP_VALUE and ARG_PTR_TO_MAP_VALUE_OR_NULL
		newArg.CanBeNull = false
	}
	return newArg
}

type BpfCall struct {
	Helper       *BpfHelper
	Args         []*BpfArg
	ArgMap       *BpfMap
	Ret          string
	RetType      string //XXX switch to StructDef
	StackVarSize int
	Hint         *BpfCallGenHint
	PostCalls    []*BpfCall
}

func NewBpfCall(helper *BpfHelper, hint *BpfCallGenHint) *BpfCall {
	newCall := &BpfCall{
		Helper: helper,
		Args: make([]*BpfArg, len(helper.Args)),
		Hint: hint,
	}
	return newCall
}

func (call *BpfCall) getArgConstraints(p *BpfProg) []string {
	var constraints []string
	for _, arg := range call.Args {
		if arg.IsPktMetaAccess {
			constraints = append(constraints, fmt.Sprintf("%v + %v < %v", p.CtxVars["data_meta"], arg.AccessSize, p.CtxVars["data"]))
			continue
		}
		if arg.IsPktAccess {
			constraints = append(constraints, fmt.Sprintf("%v + %v < %v", p.CtxVars["data"], arg.AccessSize, p.CtxVars["data_end"]))
			continue
		}
		//if !arg.CanBeNull && !arg.IsNotNull && strings.Contains(arg.ArgType, "ARG_PTR_TO") {
		if !arg.CanBeNull && !arg.IsNotNull {
			varStart := strings.Index(arg.Name, "&") + 1
			if idx := strings.Index(arg.Name, "->"); idx != -1 {
				constraints = append(constraints, fmt.Sprintf("%v", arg.Name[varStart:idx]))
			} else {
				constraints = append(constraints, fmt.Sprintf("%v", arg.Name[varStart:len(arg.Name)]))
			}
			continue
		}
		if arg.Umin != int64(-1) {
			if arg.Umin == int64(0) {
				constraints = append(constraints, fmt.Sprintf("(%v != 0 && (%v & 0x8000000000000000UL == 0))", arg.Name, arg.Name))
			} else {
				constraints = append(constraints, fmt.Sprintf("%v > %v", arg.Name, arg.Umin)) //XXX potential mutation point
			}
		}
		if arg.Umax != int64(-1) {
			constraints = append(constraints, fmt.Sprintf("%v < %v", arg.Name, arg.Umax))
		}
	}
	return constraints
}

//XXX use prog.Arg
type StructDef struct {
	Name       string
        FieldNames []string
        FieldTypes []string
	Size       int
	Hints      map[ArgHint]bool
	IsStruct   bool
}

func (sd *StructDef) offsetOfMember(mi int) int {
	offset := 0
	for i := 0; i < mi; i++ {
		switch (sd.FieldTypes[i]) {
		case "struct bpf_spin_lock": offset += 4
		case "struct bpf_timer": offset += 16
		case "char [8]": offset += 8
		case "uint64_t": offset += 8
		case "uint32_t": offset += 4
		case "uint16_t": offset += 2
		case "uint8_t": offset += 1
		}
	}
	return offset
}

func (sd *StructDef) findMember(m string) int {
	for i, mt := range sd.FieldTypes {
		if mt == m {
			return i
		}
	}
	return -1
}

func occupiedSize(hints map[ArgHint]bool) int {
	occupied := 0
	if _, ok := hints[HintGenSpinlock]; ok {
		occupied += 4
	}
	if _, ok := hints[HintGenTimer]; ok {
		occupied += 16
	}
	if _, ok := hints[HintGenConstStr]; ok {
		occupied += 8
	}
	return occupied
}

func NewBpfProg(pt *BpfProgType, r *randGen, opt BrfGenProgOpt) *BpfProg {
	p := &BpfProg{
		pt: pt,
		Externs: make(map[string]string),
		CtxVars: make(map[string]string),
		CtxTypes: make(map[string]string),
	}

	if (opt.useTestSrc) {
		p.BasePath = opt.basePath + "/test_prog"
		p.UseTestSrc = true
	} else {
		p.BasePath = opt.basePath + fmt.Sprintf("/prog_%x", time.Now().UnixNano())
	}

	if r != nil {
		p.RetVal = genRandReturnVal(r, pt.Enum)
		p.Sec = pt.SecDefs[r.Intn(len(pt.SecDefs))]
		if p.Sec.SecDefGen != nil {
			name, _ := p.Sec.SecDefGen(r)
			p.SecStr = fmt.Sprintf("SEC(\"%s%s\")\n", p.Sec.Sec, name)
		} else {
			p.SecStr = fmt.Sprintf("SEC(\"%s\")\n", p.Sec.Sec)
		}
	}
	return p
}

func (p *BpfProg) NewMap(newMapType BpfMapType, hint *BpfCallGenHint, minValSize int, r *randGen) *BpfMap {
	mapType := newMapType.Name
	maxEntries := int64(0)
	if newMapType.MaxEntries == -1 {
		maxEntries = int64(r.Intn(1 << 10)) // XXX negative?
	} else if newMapType.MaxEntries == 0 {
		maxEntries = int64(0)
	} else if newMapType.Name == "BPF_MAP_TYPE_RINGBUF" {
		maxEntries = (int64(1) << r.Intn(newMapType.MaxEntries)) * 4096
	} else {
		maxEntries = int64(r.Intn(newMapType.MaxEntries))
	}
	if _, ok := hint.ArgHints[HintGenConstStr]; ok {
		maxEntries = 1
	}

	kok := false
	var mapKey *StructDef
	compatKeyStructs := getCompatKeyStructDefs(p, newMapType);
	if r.Intn(2) == 1 && len(compatKeyStructs) > 0 {
		mapKey = compatKeyStructs[r.Intn(len(compatKeyStructs))]
	} else {
		mapKey, kok = generateStruct(p, r, newMapType.KeySize, hint.ArgHints, false, 0)
		if !kok {
			return nil
		}
	}

	vok := false
	var mapVal *StructDef
	compatValStructs := getCompatValStructDefs(p, hint, minValSize, newMapType);
	if r.Intn(2) == 1 && len(compatValStructs) > 0 {
		mapVal = compatValStructs[r.Intn(len(compatValStructs))]
	} else {
		mapVal, vok = generateStruct(p, r, newMapType.ValSize, hint.ArgHints, true, minValSize)
		if !vok {
			return nil
		}
	}

	var innerMap *BpfMap
	if mapType == "BPF_MAP_TYPE_ARRAY_OF_MAPS" || mapType == "BPF_MAP_TYPE_HASH_OF_MAPS" {
		var innerMapHint BpfCallGenHint
		innerMapType := bpfMapTypes[r.Intn(len(bpfMapTypes))]
		innerMap = p.NewMap(innerMapType, &innerMapHint, 0, r)
	}

	var mapFlags []string
	for _, fs := range newMapType.ManFlags {
		if len(fs) == 1 {
			mapFlags = append(mapFlags, fs[0])
		} else {
			mapFlags = append(mapFlags, fs[r.Intn(len(fs))])
		}
	}
	for _, fs := range newMapType.OptFlags {
		if mapVal != nil {
			if _, ok := mapVal.Hints[HintGenConstStr]; ok && len(fs) == 2 && fs[0] == "BPF_F_WRONLY" {
				mapFlags = append(mapFlags, fs[1])
				continue
			}
		}
		if r.Intn(2) == 1 {
			continue
		}
		if len(fs) == 1 {
			mapFlags = append(mapFlags, fs[0])
		} else {
			mapFlags = append(mapFlags, fs[r.Intn(len(fs))])
		}
	}

	newMap := &BpfMap{
		Type: mapType,
		Flags: mapFlags,
		Name: fmt.Sprintf("map_%v", len(p.Maps)),
		Key: mapKey,
		Val: mapVal,
		MaxEntries: maxEntries,
		InnerMap: innerMap,
	}
	p.Maps = append(p.Maps, newMap)
	return newMap
}

func (p *BpfProg) AddMap(typ string, flags []string, name string, key *StructDef, val *StructDef, size int64) *BpfMap {
	newMap := &BpfMap{
		Name: name,
		Type: typ,
		Flags: flags,
		Key: key,
		Val: val,
		MaxEntries: size,
	}
	p.Maps = append(p.Maps, newMap)
	return newMap
}

func isPtrRegType(t RegType) bool {
	return t.String() != "SCALAR_VALUE"
}

type RegType interface {
	String() string
	Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg
	CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool
}

type ScalarValRegType struct {
}

func (t ScalarValRegType) String() string {
	return "SCALAR_VALUE"
}

func (t ScalarValRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	a := NewBpfArg(call.Helper, arg)

	size := r.Intn(64)
	if call.StackVarSize != 0 {
		size = call.StackVarSize
	}

	a.IsNotNull = true
	a.Name = fmt.Sprintf("v%d", p.VarId)
	a.Prepare = fmt.Sprintf("	int64_t %s = %d;\n", a.Name, size) // XXX does uint64 or int64 matter?
	p.VarId += 1
	return a
}

func (t ScalarValRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

var ctxStructsMap = map[string]*StructDef{
	"bpf_sock_ops": &StructDef{
		Name: "bpf_sock_ops",
		FieldTypes: []string{"uint32_t", "uint32_t [4]", "uint32_t", "uint32_t", "uint32_t", "uint32_t [4]", "uint32_t [4]", "uint32_t", "uint32_t", "uint32_t",
			"uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t",
			"uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t",
			"uint32_t", "uint32_t", "uint32_t", "uint64_t", "uint64_t", "struct bpf_sock*", "void*", "void*", "uint32_t", "uint32_t"},
		FieldNames: []string{"op", "args", "family", "remote_ip4", "local_ip4", "remote_ip6", "local_ip6", "remote_port", "local_port", "is_fullsock",
			"snd_cwnd", "srtt_us", "bpf_sock_ops_cb_flags", "state", "rtt_min", "snd_ssthresh", "rcv_nxt", "snd_nxt", "snd_una", "mss_cache",
			"ecn_flags", "rate_delivered", "rate_interval_us", "packets_out", "retrans_out", "total_retrans", "segs_in", "data_segs_in", "segs_out", "data_segs_out",
			"lost_out", "sacked_out", "sk_txhash", "bytes_received", "bytes_acked", "sk", "skb_data", "skb_data_end", "skb_len", "skb_tcp_flags"},
		Size: 216,
		IsStruct: true,
	},
	"sk_reuseport_md": &StructDef{
		Name: "sk_reuseport_md",
		FieldTypes: []string{"void *", "void *", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "struct bpf_sock*", "struct bpf_sock*"},
		FieldNames: []string{"data", "data_end", "len", "eth_protocol", "ip_protocol", "bind_inany", "hash", "sk", "migrating_sk"},
		Size: 52,
		IsStruct: true,
	},
	"sk_msg_md": &StructDef{
		Name: "sk_msg_md",
		FieldTypes: []string{"void *", "void *", "uint32_t", "uint32_t", "uint32_t", "uint32_t [4]", "uint32_t [4]", "uint32_t", "uint32_t", "uint32_t",
			"struct bpf_sock*"},
		FieldNames: []string{"data", "data_end", "family", "remote_ip4", "local_ip4", "remote_ip6", "local_ip6", "remote_port", "local_port", "size",
			"sk"},
		Size: 80,
		IsStruct: true,
	},
	"__sk_buff": &StructDef{
		Name: "__sk_buff",
		FieldTypes: []string{"uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t",
			"uint32_t", "uint32_t", "uint32_t [5]", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t",
			"uint32_t", "uint32_t [4]", "uint32_t [4]", "uint32_t", "uint32_t", "uint32_t", "struct bpf_flow_keys*", "uint64_t", "uint32_t", "uint32_t",
			"struct bpf_sock*", "uint32_t"},
		FieldNames: []string{"len", "pkt_type", "mark", "queue_mapping", "protocol", "vlan_present", "vlan_tci", "vlan_proto", "priority", "ingress_ifindex",
			"ifindex", "tc_index", "cb", "hash", "tc_classid", "data", "data_end", "napi_id", "family", "remote_ip4",
			"local_ip4", "remote_ip6", "local_ip6", "remote_port", "local_port", "data_meta", "flow_keys", "tstamp", "wire_len", "gso_segs",
			"sk", "gso_size"},
		Size: 180,
		IsStruct: true,
	},
	"bpf_sock": &StructDef{
		Name: "bpf_sock",
		FieldTypes: []string{"uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t [4]", "uint32_t", "uint32_t",
			"uint32_t", "uint32_t [4]", "uint32_t", "int32_t"},
		FieldNames: []string{"bound_dev_if", "family", "type", "protocol", "mark", "priority", "src_ip4", "src_ip6", "src_port", "dst_port",
			"dst_ip4", "dst_ip6", "state", "rx_queue_mapping"},
		Size: 80,
		IsStruct: true,
	},
	"bpf_raw_tracepoint_args": &StructDef{
		Name: "bpf_raw_tracepoint_args",
		FieldTypes: []string{"uint64_t [0]"},
		FieldNames: []string{"args"},
		Size: 8,
		IsStruct: true,//XXX fix this
	},
	"bpf_sockopt": &StructDef{
		Name: "bpf_sockopt",
		FieldTypes: []string{"struct bpf_sock*", "void *", "void *", "int32_t", "int32_t", "int32_t", "int32_t"},
		FieldNames: []string{"sk", "optval", "optval_end", "level", "optname", "optlen", "retval"},
		Size: 40,
		IsStruct: true,
	},
	"bpf_sk_lookup": &StructDef{
		Name: "bpf_sk_lookup",
		FieldTypes: []string{"struct bpf_sock*", "uint32_t", "uint32_t", "uint32_t", "uint32_t [4]", "uint32_t", "uint32_t", "uint32_t [4]", "uint32_t"},
		FieldNames: []string{"sk", "family", "protocol", "remote_ip4", "remote_ip6", "remote_port", "local_ip4", "local_ip6", "local_port"},
		Size: 64,
		IsStruct: true,
	},
	"bpf_sock_addr": &StructDef{
		Name: "bpf_sock_addr",
		FieldTypes: []string{"uint32_t", "uint32_t", "uint32_t [4]", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t [4]", "struct bpf_sock*"},
		FieldNames: []string{"user_family", "user_ip4", "user_ip6", "user_port", "family", "type", "protocol", "msg_src_ip4", "msg_src_ip6", "sk"},
		Size: 68,
		IsStruct: true,
	},
	"bpf_perf_event_data": &StructDef{
		Name: "bpf_perf_event_data",
		FieldTypes: []string{"struct bpf_user_pt_regs_t", "uint64_t", "uint64_t"},
		FieldNames: []string{"regs", "sample_period", "addr"},
		Size: 184,
		IsStruct: true,
	},
	"bpf_sysctl": &StructDef{
		Name: "bpf_sysctl",
		FieldTypes: []string{"uint32_t", "uint32_t"},
		FieldNames: []string{"write", "file_pos"},
		Size: 8,
		IsStruct: true,
	},
	"xdp_md": &StructDef{
		Name: "xdp_md",
		FieldTypes: []string{"uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t"},
		FieldNames: []string{"data", "data_end", "data_meta", "ingress_ifindex", "rx_queue_index", "egress_ifindex"},
		Size: 24,
		IsStruct: true,
	},
	"bpf_user_pt_regs_t": &StructDef{
		Name: "bpf_user_pt_regs_t",
		FieldTypes: []string{"uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t",
			"uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t",
			"uint64_t"},
		FieldNames: []string{"r15", "r14", "r13", "r12", "bp", "bx", "r11", "r10", "r9", "r8",
			"ax", "cx", "dx", "si", "di", "orig_ax", "ip", "cs", "flags", "sp",
			"ss"},
		Size: 168,
		IsStruct: true,
	},
}

type PtrToCtxRegType struct {
}

func (t PtrToCtxRegType) String() string {
	return "PTR_TO_CTX"
}

func (t PtrToCtxRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	a := NewBpfArg(call.Helper, arg)
	//CTX access is handled by genRandBpfCtxAccess
	a.Name = fmt.Sprintf("ctx")
	a.IsNotNull = true
	return a
}

func (t PtrToCtxRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type ConstPtrToMapRegType struct {
}

func (t ConstPtrToMapRegType) String() string {
	return "CONST_PTR_TO_MAP"
}

//XXX add key, value constraints
var bpfMapTypes = []BpfMapType {
//	BpfMapType{"BPF_PROG_TYPE_UNSPEC",[]string{}},
	BpfMapType{"BPF_MAP_TYPE_HASH",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NO_PREALLOC"},[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"},[]string{"BPF_F_ZERO_SEED"}},
		   []int{1,1<<12},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_ARRAY",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_MMAPABLE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"},[]string{"BPF_F_INNER_MAP"}},
		   []int{4,4},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_PROG_ARRAY",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{4,4},[]int{4,4},-1},
	BpfMapType{"BPF_MAP_TYPE_PERF_EVENT_ARRAY",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_PRESERVE_ELEMS"}},
		   []int{4,4},[]int{4,4},-1},
	BpfMapType{"BPF_MAP_TYPE_PERCPU_HASH",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NO_PREALLOC"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"},[]string{"BPF_F_ZERO_SEED"}},
		   []int{1,1<<12},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_PERCPU_ARRAY",
		   [][]string{},
		   [][]string{[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"}},
		   []int{4,4},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_STACK_TRACE",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_RDONLY","BPF_F_WRONLY"},[]string{"BPF_F_STACK_BUILD_ID"}},
		   []int{4,4},[]int{8,1<<12,8},-1},
	BpfMapType{"BPF_MAP_TYPE_CGROUP_ARRAY",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{4,4},[]int{4,4},-1},
	BpfMapType{"BPF_MAP_TYPE_LRU_HASH",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NO_COMMON_LRU","BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"},[]string{"BPF_F_ZERO_SEED"}},
		   []int{1,1<<12},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_LRU_PERCPU_HASH",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NO_COMMON_LRU"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"},[]string{"BPF_F_ZERO_SEED"}},
		   []int{1,1<<12},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_LPM_TRIE",
		   [][]string{[]string{"BPF_F_NO_PREALLOC"}},
//		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"}},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"}},
		   []int{9,264},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_ARRAY_OF_MAPS",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{4,4},[]int{4,4},-1},
	BpfMapType{"BPF_MAP_TYPE_HASH_OF_MAPS",
		   [][]string{},
//		   [][]string{[]string{"BPF_F_NO_PREALLOC"},[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"},[]string{"BPF_F_ZERO_SEED"}},
// do not use BPF_F_RDONLY so that libbpf can fill in the inner maps
		   [][]string{[]string{"BPF_F_NO_PREALLOC"},[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"},[]string{"BPF_F_ZERO_SEED"}},
		   []int{1,1<<12},[]int{4,4},-1},
	BpfMapType{"BPF_MAP_TYPE_DEVMAP",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{4,4},[]int{4,8,4},-1},
	BpfMapType{"BPF_MAP_TYPE_SOCKMAP",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{4,4},[]int{4,8,4},-1},
	BpfMapType{"BPF_MAP_TYPE_CPUMAP",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"}},
		   []int{4,4},[]int{4,8,4},-1},
	BpfMapType{"BPF_MAP_TYPE_XSKMAP",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{4,4},[]int{4,4},-1},
	BpfMapType{"BPF_MAP_TYPE_SOCKHASH",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{1,512},[]int{4,8,4},-1},
	BpfMapType{"BPF_MAP_TYPE_CGROUP_STORAGE",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_RDONLY_PROG","BPF_F_WRONLY_PROG"}},
		   []int{8,12,4},[]int{8,1<<16},0},
	BpfMapType{"BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_WRONLY_PROG","BPF_F_RDONLY_PROG"}},
		   []int{1,1<<16},[]int{4,8,4},-1}, //XXX 16 for max for now
	BpfMapType{"BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_RDONLY_PROG","BPF_F_WRONLY_PROG"}},
		   []int{8,12,4},[]int{8,1<<16},0},
//		   []int{4,4},[]int{1,1<<16},0}, // XXX 16 for max for now
	BpfMapType{"BPF_MAP_TYPE_QUEUE",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_RDONLY_PROG"},[]string{"BPF_F_WRONLY_PROG"}},
		   []int{0,0},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_STACK",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"},[]string{"BPF_F_RDONLY_PROG"},[]string{"BPF_F_WRONLY_PROG"}},
		   []int{0,0},[]int{1,1<<12},-1},
	BpfMapType{"BPF_MAP_TYPE_SK_STORAGE",
		   [][]string{[]string{"BPF_F_NO_PREALLOC"}},
		   [][]string{[]string{"BPF_F_CLONE"}},
		   []int{4,4},[]int{1,1<<16},0}, // XXX 16 for max for now
	BpfMapType{"BPF_MAP_TYPE_DEVMAP_HASH",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"},[]string{"BPF_F_WRONLY","BPF_F_RDONLY"}},
		   []int{4,4},[]int{4,8,4},-1},
	BpfMapType{"BPF_MAP_TYPE_STRUCT_OPS",
		   [][]string{},
		   [][]string{},
		   []int{4,4},[]int{0,1<<12},1}, // XXX 12 for now
	BpfMapType{"BPF_MAP_TYPE_RINGBUF",
		   [][]string{},
		   [][]string{[]string{"BPF_F_NUMA_NODE"}},
		   []int{0,0},[]int{0,0},24}, // 1<<24
	BpfMapType{"BPF_MAP_TYPE_INODE_STORAGE",
		   [][]string{[]string{"BPF_F_NO_PREALLOC"}},
		   [][]string{[]string{"BPF_F_CLONE"}},
		   []int{4,4},[]int{1,1<<16},0}, // XXX 16 for max for now
	BpfMapType{"BPF_MAP_TYPE_TASK_STORAGE",
		   [][]string{[]string{"BPF_F_NO_PREALLOC"}},
		   [][]string{[]string{"BPF_F_CLONE"}},
		   []int{4,4},[]int{1,1<<16},0}, // XXX 16 for max for now
}

func generateStruct(p *BpfProg, r *randGen, sizeConstraints []int, hints map[ArgHint]bool, useHint bool, minSizeHint int) (*StructDef, bool) {
	min := sizeConstraints[0]
	max := sizeConstraints[1]
	align := 1
	if len(sizeConstraints) == 3 {
		align = sizeConstraints[2]
	}

	sd := new(StructDef)
	sd.Hints = make(map[ArgHint]bool)
	target := "key"
	if useHint {
		target = "val"
	}
	fmt.Printf("(%v) gen %v struct_%d initial min=%v max=%v align=%v ArgHints=%x occu=%d\n",
		rd, target, len(p.Structs), min, max, align, hints, occupiedSize(hints))

	if useHint {
		occupied := occupiedSize(hints)
		if occupied > max {
			fmt.Printf("error: map type value size not large enough to accommodate %x\n", hints)
			return nil, false
		}
		if occupied > min {
			min = occupied
		}

		if minSizeHint > max {
			fmt.Printf("error: map type size not large enough to accommodate %x\n", minSizeHint)
			return nil, false
		} else if min != max && minSizeHint > min {
			min = minSizeHint
		}
	}

	size := 0
	if min == max {
		size = min
	} else if max > min {
		// XXX Re-adjust max to 128 for now
		if max > 128 {
			max = 128
		}
		size = r.Intn(max-min+1) + min
		// adjust size according to alignment
		if align != 1 {
			size = size - (size%align)
		}
	} else {
		fmt.Printf("error: max < min\n")
		return nil, false
	}
	if size == 0 {
		return nil, true
	}
	sd.Size = size

	fmt.Printf("(%v) gen %v struct_%d adjust min=%v max=%v align=%v, size=%v\n",
		rd, target, len(p.Structs), min, max, align, size)

	offset := 0
	for {
		if offset >= size {
			break
		}
		toEnd := size - offset
		if _, ok := hints[HintGenSpinlock]; useHint && ok {
			sd.Hints[HintGenSpinlock] = true
			delete(hints, HintGenSpinlock)
			sd.FieldTypes = append(sd.FieldTypes, "struct bpf_spin_lock")
			offset += 4
		} else if _, ok := hints[HintGenTimer]; useHint && ok  {
			sd.Hints[HintGenTimer] = true
			delete(hints, HintGenTimer)
			sd.FieldTypes = append(sd.FieldTypes, "struct bpf_timer")
			offset += 16
		} else if _, ok := hints[HintGenConstStr]; useHint && ok {
			sd.Hints[HintGenConstStr] = true
			delete(hints, HintGenConstStr)
			sd.FieldTypes = append(sd.FieldTypes, "char [8]")
			offset += 8
		} else if toEnd >= 8 {
			sd.FieldTypes = append(sd.FieldTypes, "uint64_t")
			offset += 8
		} else if toEnd >= 4 {
			sd.FieldTypes = append(sd.FieldTypes, "uint32_t")
			offset += 4
		} else if toEnd >= 2 {
			sd.FieldTypes = append(sd.FieldTypes, "uint16_t")
			offset += 2
		} else {
			sd.FieldTypes = append(sd.FieldTypes, "uint8_t")
			offset += 1
		}
	}

	if len(sd.FieldTypes) == 1 {
		sd.IsStruct = false
		sd.Name = fmt.Sprintf("%v", sd.FieldTypes[0])
	} else {
		sd.IsStruct = true
		sd.Name = fmt.Sprintf("struct_%d", len(p.Structs))
	}

	p.Structs = append(p.Structs, sd)
	return sd, true
}

var mayUpdateSockmapProgs = map[BpfProgTypeEnum]bool {
	BPF_PROG_TYPE_TRACING: true,
//	if (eatype == BPF_TRACE_ITER)
	BPF_PROG_TYPE_SOCKET_FILTER: true,
	BPF_PROG_TYPE_SCHED_CLS: true,
	BPF_PROG_TYPE_SCHED_ACT: true,
	BPF_PROG_TYPE_XDP: true,
	BPF_PROG_TYPE_SK_REUSEPORT: true,
	BPF_PROG_TYPE_FLOW_DISSECTOR: true,
	BPF_PROG_TYPE_SK_LOOKUP: true,
}

var funcCompMaps = map[BpfHelperEnum][]string {
	BPF_FUNC_tail_call: []string{"BPF_MAP_TYPE_PROG_ARRAY"},
	BPF_FUNC_perf_event_read: []string{"BPF_MAP_TYPE_PERF_EVENT_ARRAY"},
	BPF_FUNC_perf_event_output: []string{"BPF_MAP_TYPE_PERF_EVENT_ARRAY"},
	BPF_FUNC_perf_event_read_value: []string{"BPF_MAP_TYPE_PERF_EVENT_ARRAY"},
	BPF_FUNC_skb_output: []string{"BPF_MAP_TYPE_PERF_EVENT_ARRAY"},
	BPF_FUNC_xdp_output: []string{"BPF_MAP_TYPE_PERF_EVENT_ARRAY"},
	BPF_FUNC_ringbuf_output: []string{"BPF_MAP_TYPE_RINGBUF"},
	BPF_FUNC_ringbuf_reserve: []string{"BPF_MAP_TYPE_RINGBUF"},
	BPF_FUNC_ringbuf_query: []string{"BPF_MAP_TYPE_RINGBUF"},
	BPF_FUNC_get_stackid: []string{"BPF_MAP_TYPE_STACK_TRACE"},
	BPF_FUNC_current_task_under_cgroup: []string{"BPF_MAP_TYPE_CGROUP_ARRAY"},
	BPF_FUNC_skb_under_cgroup: []string{"BPF_MAP_TYPE_CGROUP_ARRAY"},
	BPF_FUNC_redirect_map: []string{"BPF_MAP_TYPE_DEVMAP","BPF_MAP_TYPE_DEVMAP_HASH","BPF_MAP_TYPE_CPUMAP","BPF_MAP_TYPE_XSKMAP"},
	BPF_FUNC_sk_redirect_map: []string{"BPF_MAP_TYPE_SOCKMAP"},
	BPF_FUNC_msg_redirect_map: []string{"BPF_MAP_TYPE_SOCKMAP"},
	BPF_FUNC_sock_map_update: []string{"BPF_MAP_TYPE_SOCKMAP"},
	BPF_FUNC_sk_redirect_hash: []string{"BPF_MAP_TYPE_SOCKHASH"},
	BPF_FUNC_msg_redirect_hash: []string{"BPF_MAP_TYPE_SOCKHASH"},
	BPF_FUNC_sock_hash_update: []string{"BPF_MAP_TYPE_SOCKHASH"},
	BPF_FUNC_get_local_storage: []string{"BPF_MAP_TYPE_CGROUP_STORAGE","BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE"},
	BPF_FUNC_sk_select_reuseport: []string{"BPF_MAP_TYPE_REUSEPORT_SOCKARRAY","BPF_MAP_TYPE_SOCKMAP","BPF_MAP_TYPE_SOCKHASH"},
	BPF_FUNC_map_peek_elem: []string{"BPF_MAP_TYPE_QUEUE","BPF_MAP_TYPE_STACK"},
	BPF_FUNC_map_pop_elem: []string{"BPF_MAP_TYPE_QUEUE","BPF_MAP_TYPE_STACK"},
	BPF_FUNC_map_push_elem: []string{"BPF_MAP_TYPE_QUEUE","BPF_MAP_TYPE_STACK"},
	BPF_FUNC_sk_storage_get: []string{"BPF_MAP_TYPE_SK_STORAGE"},
	BPF_FUNC_sk_storage_delete: []string{"BPF_MAP_TYPE_SK_STORAGE"},
	BPF_FUNC_inode_storage_get: []string{"BPF_MAP_TYPE_INODE_STORAGE"},
	BPF_FUNC_inode_storage_delete: []string{"BPF_MAP_TYPE_INODE_STORAGE"},
	BPF_FUNC_task_storage_get: []string{"BPF_MAP_TYPE_TASK_STORAGE"},
	BPF_FUNC_task_storage_delete: []string{"BPF_MAP_TYPE_TASK_STORAGE"},
}

var mapCompFuncs = map[string][]BpfHelperEnum {
	"BPF_MAP_TYPE_PROG_ARRAY": []BpfHelperEnum{BPF_FUNC_tail_call},
	"BPF_MAP_TYPE_PERF_EVENT_ARRAY": []BpfHelperEnum{BPF_FUNC_perf_event_read,BPF_FUNC_perf_event_output,BPF_FUNC_skb_output,BPF_FUNC_perf_event_read_value,BPF_FUNC_xdp_output},
	"BPF_MAP_TYPE_RINGBUF": []BpfHelperEnum{BPF_FUNC_ringbuf_output,BPF_FUNC_ringbuf_reserve,BPF_FUNC_ringbuf_query},
	"BPF_MAP_TYPE_STACK_TRACE": []BpfHelperEnum{BPF_FUNC_get_stackid},
	"BPF_MAP_TYPE_CGROUP_ARRAY": []BpfHelperEnum{BPF_FUNC_skb_under_cgroup,BPF_FUNC_current_task_under_cgroup},
	"BPF_MAP_TYPE_CGROUP_STORAGE": []BpfHelperEnum{BPF_FUNC_get_local_storage},
	"BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE": []BpfHelperEnum{BPF_FUNC_get_local_storage},
	"BPF_MAP_TYPE_DEVMAP": []BpfHelperEnum{BPF_FUNC_redirect_map,BPF_FUNC_map_lookup_elem},
	"BPF_MAP_TYPE_DEVMAP_HASH": []BpfHelperEnum{BPF_FUNC_redirect_map,BPF_FUNC_map_lookup_elem},
	"BPF_MAP_TYPE_CPUMAP": []BpfHelperEnum{BPF_FUNC_redirect_map},
	"BPF_MAP_TYPE_XSKMAP": []BpfHelperEnum{BPF_FUNC_redirect_map,BPF_FUNC_map_lookup_elem},
	"BPF_MAP_TYPE_ARRAY_OF_MAPS": []BpfHelperEnum{BPF_FUNC_map_lookup_elem},
	"BPF_MAP_TYPE_HASH_OF_MAPS": []BpfHelperEnum{BPF_FUNC_map_lookup_elem},
	"BPF_MAP_TYPE_SOCKMAP": []BpfHelperEnum{BPF_FUNC_sk_redirect_map,BPF_FUNC_sock_map_update,BPF_FUNC_map_delete_elem,BPF_FUNC_msg_redirect_map,BPF_FUNC_sk_select_reuseport,BPF_FUNC_map_lookup_elem},
	// XXX       !may_update_sockmap(env, func_id))
	"BPF_MAP_TYPE_SOCKHASH": []BpfHelperEnum{BPF_FUNC_sk_redirect_hash,BPF_FUNC_sock_hash_update,BPF_FUNC_map_delete_elem,BPF_FUNC_msg_redirect_hash,BPF_FUNC_sk_select_reuseport,BPF_FUNC_map_lookup_elem},
	// XXX       !may_update_sockmap(env, func_id))
	"BPF_MAP_TYPE_REUSEPORT_SOCKARRAY": []BpfHelperEnum{BPF_FUNC_sk_select_reuseport},
	"BPF_MAP_TYPE_QUEUE": []BpfHelperEnum{BPF_FUNC_map_peek_elem,BPF_FUNC_map_pop_elem,BPF_FUNC_map_push_elem},
	"BPF_MAP_TYPE_STACK": []BpfHelperEnum{BPF_FUNC_map_peek_elem,BPF_FUNC_map_pop_elem,BPF_FUNC_map_push_elem},
	"BPF_MAP_TYPE_SK_STORAGE": []BpfHelperEnum{BPF_FUNC_sk_storage_get,BPF_FUNC_sk_storage_delete},
	"BPF_MAP_TYPE_INODE_STORAGE": []BpfHelperEnum{BPF_FUNC_inode_storage_get,BPF_FUNC_inode_storage_delete},
	"BPF_MAP_TYPE_TASK_STORAGE": []BpfHelperEnum{BPF_FUNC_task_storage_get,BPF_FUNC_task_storage_delete},
}

func isMapFuncCompatible(m string, f BpfHelperEnum) bool {
	if maps, ok := funcCompMaps[f]; ok {
		compatible := false
		for _, cm := range maps {
			if cm == m {
				compatible = true
				break
			}
		}
		if !compatible {
			return false
		}
	}
	if funcs, ok := mapCompFuncs[m]; ok {
		compatible := false
		for _, cf := range funcs {
			if cf == f {
				compatible = true
				break
			}
		}
		if !compatible {
			return false
		}
	}
	return true
}

func getHelperCompatMaps(p *BpfProg, call *BpfCall) []*BpfMap {
	var compatMaps []*BpfMap
	for _, m := range p.Maps {
		if !isMapFuncCompatible(m.Type, call.Helper.Enum) {
			continue
		}

		mapHasSpinlock := (m.Val != nil && m.Val.findMember("struct bpf_spin_lock") != -1)
		mapHasTimer := (m.Val != nil && m.Val.findMember("struct bpf_timer") != -1)
		mapHasConstStr := (m.Val != nil && m.Val.findMember("char [8]") != -1)
		mapIsRdOnly := (m.getFlag("BPF_F_RDONLY_PROG") != -1)
		mapIsWrOnly := (m.getFlag("BPF_F_WRONLY_PROG") != -1)

		//6084
		if (call.Helper.Enum == BPF_FUNC_map_delete_elem || call.Helper.Enum == BPF_FUNC_map_update_elem ||
		    call.Helper.Enum == BPF_FUNC_map_push_elem || call.Helper.Enum == BPF_FUNC_map_pop_elem) &&
		    mapIsRdOnly {
			continue
		}
		//4706, 4767
		_, genSpinlock := call.Hint.ArgHints[HintGenSpinlock]
		_, genTimer := call.Hint.ArgHints[HintGenTimer]
		_, genConstStr := call.Hint.ArgHints[HintGenConstStr]
		if (genSpinlock && (!mapHasSpinlock || mapIsRdOnly)) ||
		   (genTimer && (!mapHasTimer || mapIsRdOnly)) ||
		   (genConstStr && !mapHasConstStr) {
			continue
		}
		//11473, 11478, 11484
		if mapHasSpinlock &&
			(p.pt.Enum == BPF_PROG_TYPE_SOCKET_FILTER || isTracingProgType(p.pt.Enum) || p.Sec.Sleepable) {
			continue
		}
		//11503
		if m.Type == "BPF_MAP_TYPE_STRUCT_OPS" {
			continue
		}
		//11526
		if p.Sec.Sleepable &&
			!(m.Type == "BPF_MAP_TYPE_HASH" || m.Type == "BPF_MAP_TYPE_LRU_HASH" || m.Type == "BPF_MAP_TYPE_ARRAY" ||
			 m.Type == "BPF_MAP_TYPE_PERCPU_HASH" || m.Type == "BPF_MAP_TYPE_PERCPU_ARRAY" || m.Type == "BPF_MAP_TYPE_LRU_PERCPU_HASH" ||
			 m.Type == "BPF_MAP_TYPE_ARRAY_OF_MAPS" || m.Type == "BPF_MAP_TYPE_HASH_OF_MAPS" || m.Type == "BPF_MAP_TYPE_RINGBUF") {
			continue
		}
		//11704
		if m.Type == "BPF_MAP_TYPE_CGROUP_STORAGE" {
			hasCgroupStorageMap := false
			for _, pm := range p.Maps {
				if pm.Type == "BPF_MAP_TYPE_CGROUP_STORAGE" {
					hasCgroupStorageMap = true
				}
			}
			if hasCgroupStorageMap {
				continue
			}
		}
		if m.Type == "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE" {
			hasPercpuCgroupStorageMap := false
			for _, pm := range p.Maps {
				if pm.Type == "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE" {
					hasPercpuCgroupStorageMap = true
				}
			}
			if hasPercpuCgroupStorageMap {
				continue
			}
		}

		_, genSockMap := call.Hint.ArgHints[HintGenSockMap]
		_, genXdpSockMap := call.Hint.ArgHints[HintGenXdpSockMap]
		if call.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
			if genXdpSockMap != (m.Type == "BPF_MAP_TYPE_XSKMAP") {
				continue
			}
			if genSockMap != (m.Type == "BPF_MAP_TYPE_SOCKMAP" || m.Type == "BPF_MAP_TYPE_SOCKHASH") {
				continue
			}
		}

		if (call.Helper.Ret == "RET_PTR_TO_MAP_VALUE" || call.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL") && call.Hint.RetAccessSize != 0 {
			if m.Val == nil || m.Val.Size < call.Hint.RetAccessSize {
				continue
			}
			if mapIsRdOnly && call.Hint.IsRetAccessRaw {
				continue
			}
			if mapIsWrOnly && !call.Hint.IsRetAccessRaw {
				continue
			}
			if call.Hint.IsRetAccessRaw && (m.Type == "BPF_MAP_TYPE_DEVMAP" || m.Type == "BPF_MAP_TYPE_DEVMAP_HASH") {
				continue
			}
		}
		compatMaps = append(compatMaps, m)
	}
	return compatMaps
}

func isTracingProgType(e BpfProgTypeEnum) bool {
	return e == BPF_PROG_TYPE_KPROBE || e == BPF_PROG_TYPE_TRACEPOINT || e == BPF_PROG_TYPE_PERF_EVENT || e == BPF_PROG_TYPE_RAW_TRACEPOINT
}

func getHelperCompatMapTypes(p *BpfProg, call *BpfCall) []BpfMapType {
	var compatMapTypes []BpfMapType
	for _, mt := range bpfMapTypes {
		if !isMapFuncCompatible(mt.Name, call.Helper.Enum) {
			continue
		}
		if mt.ValSize[1] < occupiedSize(call.Hint.ArgHints) {
			continue
		}
		if _, ok := call.Hint.ArgHints[HintGenSpinlock]; ok {
			if mt.Name != "BPF_MAP_TYPE_HASH" && mt.Name != "BPF_MAP_TYPE_ARRAY" &&
				mt.Name != "BPF_MAP_TYPE_CGROUP_STORAGE" && mt.Name != "BPF_MAP_TYPE_SK_STORAGE" &&
				mt.Name != "BPF_MAP_TYPE_INODE_STORAGE" && mt.Name != "BPF_MAP_TYPE_TASK_STORAGE" {
				continue
			}
			//11473, 11478, 11484
			if p.pt.Enum == BPF_PROG_TYPE_SOCKET_FILTER || isTracingProgType(p.pt.Enum) || p.Sec.Sleepable {
				continue
			}
		}
		if _, ok := call.Hint.ArgHints[HintGenTimer]; ok {
			if mt.Name != "BPF_MAP_TYPE_HASH" && mt.Name != "BPF_MAP_TYPE_LRU_HASH" && mt.Name != "BPF_MAP_TYPE_ARRAY" {
				continue
			}
			if isTracingProgType(p.pt.Enum) { // 11491
				continue
			}
		}
		//11503
		if mt.Name == "BPF_MAP_TYPE_STRUCT_OPS" {
			continue
		}
		//11526
		if p.Sec.Sleepable &&
			!(mt.Name == "BPF_MAP_TYPE_HASH" || mt.Name == "BPF_MAP_TYPE_LRU_HASH" || mt.Name == "BPF_MAP_TYPE_ARRAY" ||
			 mt.Name == "BPF_MAP_TYPE_PERCPU_HASH" || mt.Name == "BPF_MAP_TYPE_PERCPU_ARRAY" || mt.Name == "BPF_MAP_TYPE_LRU_PERCPU_HASH" ||
			 mt.Name == "BPF_MAP_TYPE_ARRAY_OF_MAPS" || mt.Name == "BPF_MAP_TYPE_HASH_OF_MAPS" || mt.Name == "BPF_MAP_TYPE_RINGBUF") {
			continue
		}
		//11704
		if mt.Name == "BPF_MAP_TYPE_CGROUP_STORAGE" {
			hasCgroupStorageMap := false
			for _, pm := range p.Maps {
				if pm.Type == "BPF_MAP_TYPE_CGROUP_STORAGE" {
					hasCgroupStorageMap = true
				}
			}
			if hasCgroupStorageMap {
				continue
			}
		}
		if mt.Name == "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE" {
			hasPercpuCgroupStorageMap := false
			for _, pm := range p.Maps {
				if pm.Type == "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE" {
					hasPercpuCgroupStorageMap = true
				}
			}
			if hasPercpuCgroupStorageMap {
				continue
			}
		}
		_, genSockMap := call.Hint.ArgHints[HintGenSockMap]
		_, genXdpSockMap := call.Hint.ArgHints[HintGenXdpSockMap]
		if call.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
			if genXdpSockMap != (mt.Name == "BPF_MAP_TYPE_XSKMAP") {
				continue
			}
			if genSockMap != (mt.Name == "BPF_MAP_TYPE_SOCKMAP" || mt.Name == "BPF_MAP_TYPE_SOCKHASH") {
				continue
			}
		}
		if call.Hint.IsRetAccessRaw && (mt.Name == "BPF_MAP_TYPE_DEVMAP" || mt.Name == "BPF_MAP_TYPE_DEVMAP_HASH") {
			continue
		}
		// check if the current program type permits updating sockmap
		if call.Helper.Enum == BPF_FUNC_map_update_elem && (mt.Name == "BPF_MAP_TYPE_SOCKMAP" || mt.Name == "BPF_MAP_TYPE_SOCKHASH") {
			if _, ok := mayUpdateSockmapProgs[p.pt.Enum]; !ok {
				continue
			}
		}
		compatMapTypes = append(compatMapTypes, mt)
	}
	return compatMapTypes
}

func getCompatKeyStructDefs(p *BpfProg, mapType BpfMapType) []*StructDef {
	var compatStructs []*StructDef
	for _, structDef := range p.Structs {
		if structDef.Size < mapType.KeySize[0] || structDef.Size > mapType.KeySize[1] {
			continue
		}
		compatStructs = append(compatStructs, structDef)
	}
	return compatStructs
}

func getCompatValStructDefs(p *BpfProg, hint *BpfCallGenHint, minValSize int, mapType BpfMapType) []*StructDef {
	var compatStructs []*StructDef
	for _, structDef := range p.Structs {
		//if (call.Helper.Ret == "RET_PTR_TO_MAP_VALUE" || call.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL") &&
		//	structDef.Size < call.Hint.RetAccessSize {
		//	continue
		//}
		if minValSize != -1 && structDef.Size < minValSize {
			continue
		}
		if _, ok := hint.ArgHints[HintGenSpinlock]; ok &&
			structDef.findMember("struct bpf_spin_lock") == -1 {
			continue
		}
		if _, ok := hint.ArgHints[HintGenTimer]; ok &&
			structDef.findMember("struct bpf_timer") == -1 {
			continue
		}
		if _, ok := hint.ArgHints[HintGenConstStr]; ok &&
			structDef.findMember("char [8]") == -1 {
			continue
		}
		if _, ok := hint.ArgHints[HintGenSockMap]; ok {
			continue
		}
		if _, ok := hint.ArgHints[HintGenXdpSockMap]; ok {
			continue
		}
		if structDef.Size < mapType.ValSize[0] || structDef.Size > mapType.ValSize[1] {
			continue
		}
		if len(mapType.KeySize) == 3 && structDef.Size % mapType.KeySize[2] != 0 {
			continue
		}
		compatStructs = append(compatStructs, structDef)
	}
	return compatStructs
}

func (t ConstPtrToMapRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	a := NewBpfArg(call.Helper, arg)
	a.IsNotNull = true

	if call.Hint.PreferredMap != nil {
		call.ArgMap = call.Hint.PreferredMap
		a.Name = fmt.Sprintf("&%v", call.ArgMap.Name)
		return a
	}

	if call.ArgMap != nil {
		a.Name = fmt.Sprintf("&%v", call.ArgMap.Name)
		return a
	}

	var m *BpfMap

	if compatMaps := getHelperCompatMaps(p, call); len(compatMaps) != 0 && r.nOutOf(2, 3) {
		// Choose an existing map 
		m = compatMaps[r.Intn(len(compatMaps))]
	} else {
		// Use a newly generated map
		var newMapType BpfMapType
		compatMapTypes := getHelperCompatMapTypes(p, call)
		if len(compatMapTypes) == 0 {
			return nil// XXX failed
		}

		if _, ok := call.Hint.ArgHints[HintGenConstStr]; ok {
			mapTypeArrayIdx := -1
			for mi, mt := range compatMapTypes {
				if mt.Name == "BPF_MAP_TYPE_ARRAY" {
					mapTypeArrayIdx = mi
					break
				}
			}
			if mapTypeArrayIdx == -1 {
				return nil
			}
			newMapType = compatMapTypes[mapTypeArrayIdx]
		} else {
			newMapType = compatMapTypes[r.Intn(len(compatMapTypes))]
		}

		minValSize := -1
		if call.Helper.Ret == "RET_PTR_TO_MAP_VALUE" || call.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
			minValSize = call.Hint.RetAccessSize
		}
		m = p.NewMap(newMapType, call.Hint, minValSize, r)

		if m == nil {
			return nil
		}

		if call.Helper.Enum == BPF_FUNC_map_delete_elem || call.Helper.Enum == BPF_FUNC_map_update_elem ||
		    call.Helper.Enum == BPF_FUNC_map_push_elem || call.Helper.Enum == BPF_FUNC_map_pop_elem {
			m.removeFlag("BPF_F_RDONLY_PROG")
		}
		//4706,4767
		if m.Val != nil && (m.Val.findMember("struct bpf_spin_lock") != -1 || m.Val.findMember("struct bpf_timer") != -1) {
			m.removeFlag("BPF_F_RDONLY_PROG")
		}
		//11461
		if p.pt.Enum == BPF_PROG_TYPE_PERF_EVENT &&
			(newMapType.Name == "BPF_MAP_TYPE_HASH" || newMapType.Name == "BPF_MAP_TYPE_PERCPU_HASH" || newMapType.Name == "BPF_MAP_TYPE_HASH_OF_MAPS") {
			m.removeFlag("BPF_F_NO_PREALLOC")
		}
		//11518
		if p.Sec.Sleepable &&
			(newMapType.Name == "BPF_MAP_TYPE_HASH" || newMapType.Name == "BPF_MAP_TYPE_LRU_HASH" || newMapType.Name == "BPF_MAP_TYPE_ARRAY" ||
			 newMapType.Name == "BPF_MAP_TYPE_PERCPU_HASH" || newMapType.Name == "BPF_MAP_TYPE_PERCPU_ARRAY" || newMapType.Name == "BPF_MAP_TYPE_LRU_PERCPU_HASH" ||
			 newMapType.Name == "BPF_MAP_TYPE_ARRAY_OF_MAPS" || newMapType.Name == "BPF_MAP_TYPE_HASH_OF_MAPS") {
			m.removeFlag("BPF_F_NO_PREALLOC")
		}
	}
	call.ArgMap = m
	a.Name = fmt.Sprintf("&%v", m.Name)
	return a
}

func (t ConstPtrToMapRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type PtrToMapValueRegType struct {
}

func (t PtrToMapValueRegType) String() string {
	return "PTR_TO_MAP_VALUE"
}

func (t PtrToMapValueRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	//XXX Consider record loaded map values and reuse them
	return nil
}

func (t PtrToMapValueRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type PtrToStackRegType struct {
}

func (t PtrToStackRegType) String() string {
	return "PTR_TO_STACK"
}

func roundUp(val int, align int) int {
	ret := val / align
	if val % align != 0 {
		ret += 1
	}
	return ret * align
}

func (t PtrToStackRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	a := NewBpfArg(call.Helper, arg)

	varSize := r.Intn(64)
	if call.ArgMap != nil {
		if call.Helper.Args[arg] == "ARG_PTR_TO_MAP_KEY" && call.ArgMap.Key != nil {
			varSize = roundUp(call.ArgMap.Key.Size, 8) //XXX need to round up key size?
		}
		if (call.Helper.Args[arg] == "ARG_PTR_TO_MAP_VALUE" || call.Helper.Args[arg] == "ARG_PTR_TO_MAP_VALUE_OR_NULL" || call.Helper.Args[arg] == "ARG_PTR_TO_UNINIT_MAP_VALUE") && call.ArgMap.Val != nil {
			varSize = roundUp(call.ArgMap.Val.Size, 8)
		}
	}

	call.StackVarSize = varSize
	a.IsNotNull = true
	a.Name = fmt.Sprintf("v%d", p.VarId)
	a.Prepare = fmt.Sprintf("	char %p[%d] = {};\n", a.Name, varSize)
	p.VarId += 1
	return a
}

func (t PtrToStackRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

var PktPtrReadOnly = map[BpfProgTypeEnum]bool {
	BPF_PROG_TYPE_LWT_IN: true,
	BPF_PROG_TYPE_LWT_OUT: true,
	BPF_PROG_TYPE_LWT_SEG6LOCAL: true,
	BPF_PROG_TYPE_SK_REUSEPORT: true,
	BPF_PROG_TYPE_FLOW_DISSECTOR: true,
	BPF_PROG_TYPE_CGROUP_SKB: true,
}

var PktPtrReadWrite = map[BpfProgTypeEnum]bool {
	BPF_PROG_TYPE_SCHED_CLS: true,
	BPF_PROG_TYPE_SCHED_ACT: true,
	BPF_PROG_TYPE_XDP: true,
	BPF_PROG_TYPE_LWT_XMIT: true,
	BPF_PROG_TYPE_SK_SKB: true,
	BPF_PROG_TYPE_SK_MSG: true,
}

var PktPtrReadWriteNoCheck = map[BpfProgTypeEnum]bool {
	BPF_PROG_TYPE_CGROUP_SOCKOPT: true,
}

func checkPktAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	canWrite := true
	if _, ok := PktPtrReadOnly[p.pt.Enum]; ok {
		canWrite = false
	} else if _, ok := PktPtrReadWrite[p.pt.Enum]; ok {
		canWrite = true
	} else if _, ok := PktPtrReadWriteNoCheck[p.pt.Enum]; ok {
		return true
	} else {
		return false
	}

	if (!canWrite && isWrite) {
		return false
	} else {
		return h.PktAccess
	}
}

type PtrToPacketMetaRegType struct {
}

func (t PtrToPacketMetaRegType) String() string {
	return "PTR_TO_PACKET_META"
}

func (t PtrToPacketMetaRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToPacketMetaRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return checkPktAccess(p, h, isWrite)
}

type PtrToPacketRegType struct {
}

func (t PtrToPacketRegType) String() string {
	return "PTR_TO_PACKET"
}

func (t PtrToPacketRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToPacketRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return checkPktAccess(p, h, isWrite)
}

type PtrToPacketEndRegType struct {
}

func (t PtrToPacketEndRegType) String() string {
	return "PTR_TO_PACKET_END"
}

func (t PtrToPacketEndRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToPacketEndRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	//XXX not found in check_mem_access
	return false
}

type PtrToFlowKeysRegType struct {
}

func (t PtrToFlowKeysRegType) String() string {
	return "PTR_TO_FLOW_KEYS"
}

func (t PtrToFlowKeysRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToFlowKeysRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type PtrToSocketRegType struct {
}

func (t PtrToSocketRegType) String() string {
	return "PTR_TO_SOCKET"
}

func (t PtrToSocketRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToSocketRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return !isWrite
}

type PtrToSockCommonRegType struct {
}

func (t PtrToSockCommonRegType) String() string {
	return "PTR_TO_SOCK_COMMON"
}

func (t PtrToSockCommonRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToSockCommonRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return !isWrite
}

type PtrToTcpSockRegType struct {
}

func (t PtrToTcpSockRegType) String() string {
	return "PTR_TO_TCP_SOCK"
}

func (t PtrToTcpSockRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToTcpSockRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return !isWrite
}

type PtrToTpBufferRegType struct {
}

func (t PtrToTpBufferRegType) String() string {
	return "PTR_TO_TP_BUFFER"
}

func (t PtrToTpBufferRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToTpBufferRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type PtrToXdpSockRegType struct {
}

func (t PtrToXdpSockRegType) String() string {
	return "PTR_TO_XDP_SOCK"
}

func (t PtrToXdpSockRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToXdpSockRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return !isWrite
}

type PtrToBtfIdRegType struct {
}

func (t PtrToBtfIdRegType) String() string {
	return "PTR_TO_BTF_ID"
}

func (t PtrToBtfIdRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToBtfIdRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type PtrToMemRegType struct {
}

func (t PtrToMemRegType) String() string {
	return "PTR_TO_ALLOC_MEM"
}

func (t PtrToMemRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToMemRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type PtrToRdOnlyBufRegType struct {
}

func (t PtrToRdOnlyBufRegType) String() string {
	return "PTR_TO_RDONLY_BUF"
}

func (t PtrToRdOnlyBufRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToRdOnlyBufRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return !isWrite
}

type PtrToRdWrBufRegType struct {
}

func (t PtrToRdWrBufRegType) String() string {
	return "PTR_TO_RDWR_BUF"
}

func (t PtrToRdWrBufRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToRdWrBufRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return true
}

type PtrToPercpuBtfIdRegType struct {
}

func (t PtrToPercpuBtfIdRegType) String() string {
	return "PTR_TO_PERCPU_BTF_ID"
}

func (t PtrToPercpuBtfIdRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	a := NewBpfArg(call.Helper, arg)
	p.Externs["bpf_prog_active"] = "int"
	a.IsNotNull = true
	a.Name = fmt.Sprintf("&bpf_prog_active")
	return a
}

func (t PtrToPercpuBtfIdRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	//XXX not found in check_mem_access
	return false
}

type PtrToFuncRegType struct {
}

func (t PtrToFuncRegType) String() string {
	return "PTR_TO_FUNC"
}

func (t PtrToFuncRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToFuncRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	//XXX not found in check_mem_access
	return false
}

type PtrToMapKeyRegType struct {
}

func (t PtrToMapKeyRegType) String() string {
	return "PTR_TO_MAP_KEY"
}

func (t PtrToMapKeyRegType) Generate(p *BpfProg, r *randGen, call *BpfCall, arg int) *BpfArg {
	return nil
}

func (t PtrToMapKeyRegType) CheckAccess(p *BpfProg, h *BpfHelper, isWrite bool) bool {
	return !isWrite
}

type BpfCtxAccessAttr struct {
	rangeInCtx   []string
	canRead      bool
	canWrite     bool
        size         int	//exact size check
        defaultSize  int	//for wide/narrow access check
	wideAccess   bool	//wide access check
	narrowAccess bool	//narrow access check
	regType      RegType
	attachTypes  []string
}

type BpfCtxAccess struct {
	regTypeMap map[string][][]string
	others     map[string]*BpfCtxAccess
	accesses   []BpfCtxAccessAttr
}

func NewBpfCtxAccess() *BpfCtxAccess {
	newCtxAccess := &BpfCtxAccess{
		regTypeMap: make(map[string][][]string),
		others: make(map[string]*BpfCtxAccess),
	}
	return newCtxAccess
}

var Brf *BpfRuntimeFuzzer

func InitBrf(enable bool) {
	Brf = NewBpfRuntimeFuzzer(enable)

	Brf.InitFromSrc(HelperFuncMap, ProgTypeMap, CtxAccessMap)
}

var map_key_value_types = []RegType{
	PtrToStackRegType{},
	PtrToPacketRegType{},
	PtrToPacketMetaRegType{},
	PtrToMapKeyRegType{},
	PtrToMapValueRegType{},
}

var scalar_types = []RegType{ScalarValRegType{}}

var const_map_ptr_types = []RegType{ConstPtrToMapRegType{}}

var context_types = []RegType{PtrToCtxRegType{}}

var sock_types = []RegType{
	PtrToSockCommonRegType{},
	PtrToSocketRegType{},
	PtrToTcpSockRegType{},
	PtrToXdpSockRegType{},
}

var btf_id_sock_common_types = []RegType{
	PtrToSockCommonRegType{},
	PtrToSocketRegType{},
	PtrToTcpSockRegType{},
	PtrToXdpSockRegType{},
	PtrToBtfIdRegType{},
}

var fullsock_types = []RegType{PtrToSocketRegType{}}

var btf_ptr_types = []RegType{PtrToBtfIdRegType{}}

var spin_lock_types = []RegType{PtrToMapValueRegType{}}

var mem_types = []RegType{
	PtrToStackRegType{},
	PtrToPacketRegType{},
	PtrToPacketMetaRegType{},
	PtrToMapKeyRegType{},
	PtrToMapValueRegType{},
	PtrToMemRegType{},
	PtrToRdOnlyBufRegType{},
	PtrToRdWrBufRegType{},
}

var alloc_mem_types = []RegType{PtrToMemRegType{}}

var int_ptr_types = []RegType{
	PtrToStackRegType{},
	PtrToPacketRegType{},
	PtrToPacketMetaRegType{},
	PtrToMapKeyRegType{},
	PtrToMapValueRegType{},
}

var percpu_btf_ptr_types = []RegType{PtrToPercpuBtfIdRegType{}}

var func_ptr_types = []RegType{PtrToFuncRegType{}}

var stack_ptr_types = []RegType{PtrToStackRegType{}}

var const_str_ptr_types = []RegType{PtrToMapValueRegType{}}

var timer_types = []RegType{PtrToMapValueRegType{}}

var all_types = []RegType{
	ScalarValRegType{},
	PtrToCtxRegType{},
	ConstPtrToMapRegType{},
	PtrToMapValueRegType{},
	PtrToStackRegType{},
	PtrToPacketMetaRegType{},
	PtrToPacketRegType{},
	PtrToPacketEndRegType{},
	PtrToFlowKeysRegType{},
	PtrToSocketRegType{},
	PtrToSockCommonRegType{},
	PtrToTcpSockRegType{},
	PtrToTpBufferRegType{},
	PtrToXdpSockRegType{},
	PtrToBtfIdRegType{},
	PtrToMemRegType{},
	PtrToRdOnlyBufRegType{},
	PtrToRdWrBufRegType{},
	PtrToPercpuBtfIdRegType{},
	PtrToFuncRegType{},
	PtrToMapKeyRegType{},
}

var compatibleRegType = map[string][]RegType {
	"ARG_ANYTHING": all_types,
	"ARG_PTR_TO_MAP_KEY": map_key_value_types,
	"ARG_PTR_TO_MAP_VALUE": map_key_value_types,
	"ARG_PTR_TO_UNINIT_MAP_VALUE": map_key_value_types,
	"ARG_PTR_TO_MAP_VALUE_OR_NULL": map_key_value_types,
	"ARG_CONST_SIZE": scalar_types,
	"ARG_CONST_SIZE_OR_ZERO": scalar_types,
	"ARG_CONST_ALLOC_SIZE_OR_ZERO": scalar_types,
	"ARG_CONST_MAP_PTR": const_map_ptr_types,
	"ARG_PTR_TO_CTX": context_types,
	"ARG_PTR_TO_CTX_OR_NULL": context_types,
	"ARG_PTR_TO_SOCK_COMMON": sock_types,
	"ARG_PTR_TO_BTF_ID_SOCK_COMMON": btf_id_sock_common_types,
	"ARG_PTR_TO_SOCKET": fullsock_types,
	"ARG_PTR_TO_SOCKET_OR_NULL": fullsock_types,
	"ARG_PTR_TO_BTF_ID": btf_ptr_types,
	"ARG_PTR_TO_SPIN_LOCK": spin_lock_types,
	"ARG_PTR_TO_MEM": mem_types,
	"ARG_PTR_TO_MEM_OR_NULL": mem_types,
	"ARG_PTR_TO_UNINIT_MEM": mem_types,
	"ARG_PTR_TO_ALLOC_MEM": alloc_mem_types,
	"ARG_PTR_TO_ALLOC_MEM_OR_NULL": alloc_mem_types,
	"ARG_PTR_TO_INT": int_ptr_types,
	"ARG_PTR_TO_LONG": int_ptr_types,
	"ARG_PTR_TO_PERCPU_BTF_ID": percpu_btf_ptr_types,
	"ARG_PTR_TO_FUNC": func_ptr_types,
	"ARG_PTR_TO_STACK_OR_NULL": stack_ptr_types,
	"ARG_PTR_TO_CONST_STR": const_str_ptr_types,
	"ARG_PTR_TO_TIMER": timer_types,
}

func (sd *StructDef) fieldIdx(f string) int {
	fieldName := f
	if f[len(f)-1: len(f)] == "]" {
		fieldName = f[0:len(f)-3]
	}

	for i, name := range sd.FieldNames {
		if name == fieldName {
			return i
		}
	}
	fmt.Printf("cannot find field %v (%v) in %v\n", f, fieldName, sd.Name)
	return -1
}

func getCtxAccessAttr(sd *StructDef, accesses []BpfCtxAccessAttr, fieldIdx int, isWrite bool) (BpfCtxAccessAttr, int) {
	for _, fi := range accesses {
		if len(fi.rangeInCtx) == 1 && sd.fieldIdx(fi.rangeInCtx[0]) == fieldIdx && fi.canWrite == isWrite {
			return fi, 1
		} else if len(fi.rangeInCtx) == 2 && sd.fieldIdx(fi.rangeInCtx[0]) <= fieldIdx && sd.fieldIdx(fi.rangeInCtx[1]) >= fieldIdx && fi.canWrite == isWrite {
			if fi.rangeInCtx[0] == fi.rangeInCtx[1] {
				return fi, 1
			} else {
				return fi, 2
			}
		} else if fi.rangeInCtx[0] == "default" && fi.canWrite == isWrite {
			return fi, 2
		}
	}
	return BpfCtxAccessAttr{}, -1
}

func (brf *BpfRuntimeFuzzer) InitFromSrc(hMap map[string]*BpfHelper, ptMap map[BpfProgTypeEnum]*BpfProgType, caMap map[BpfProgTypeEnum]*BpfCtxAccess) {
	brf.helperFuncMap = hMap
	brf.progTypeMap = ptMap
	brf.ctxAccessMap = caMap

	for name, pt := range brf.progTypeMap {
		registered := make(map[BpfHelperEnum]bool)
		for _, proto := range pt.FuncProtos {
			helper := brf.helperFuncMap[proto]
			if _, ok := registered[helper.Enum]; !ok {
				registered[helper.Enum] = true
				pt.Helpers = append(pt.Helpers, helper)
			}
		}

		var accesses []BpfCtxAccessAttr
		pt.ctxAccess = brf.ctxAccessMap[name]
		var sd *StructDef
		var ctxStructName = pt.User
		if len(pt.User) > 6 && pt.User[0:6] == "struct" {
			sd = ctxStructsMap[pt.User[7:len(pt.User)]]
			ctxStructName = pt.User[7:len(pt.User)]
		}
		if ctxStruct, ok := ctxStructsMap[ctxStructName]; ok {
			for i, fi := range ctxStruct.FieldNames {
				if readAccess, res := getCtxAccessAttr(sd, pt.ctxAccess.accesses, i, false); res != -1 {
					if res == 2 {
						readAccess.rangeInCtx = []string{fi, fi}
					}
					accesses = append(accesses, readAccess)
				} else {
					accesses = append(accesses, BpfCtxAccessAttr{rangeInCtx: []string{fi, fi}})
				}
				if writeAccess, res := getCtxAccessAttr(sd, pt.ctxAccess.accesses, i, true); res != -1 {
					if res == 2 {
						writeAccess.rangeInCtx = []string{fi, fi}
					}
					accesses = append(accesses, writeAccess)
				} else {
					accesses = append(accesses, BpfCtxAccessAttr{rangeInCtx: []string{fi, fi}})
				}
			}
			pt.ctxAccess.accesses = accesses
		}
	}
}

func findMember(p *BpfProg, structType string, memberType string) int {
	for _, sd := range p.Structs {
		if sd.Name == structType {
			return sd.findMember(memberType)
		}
	}
	return -1
}

func (p *BpfProg) genBpfHelperCallArg(r *randGen, call *BpfCall, arg int) bool {
	argType := call.Helper.Args[arg]
	fmt.Printf("(%v) gen call[%v] arg[%v]=%v (%v)\n", rd, len(p.Calls), arg, argType, call.Helper.Enum)

	var a *BpfArg
	ok := false
	if !ok && call.Helper.Enum == BPF_FUNC_get_local_storage && arg == 1 {//6311
		a = NewBpfArg(call.Helper, arg)
		a.Name = "0"
		a.IsNotNull = true
		ok = true
	}
	if !ok && r.nOutOf(1, 3) {
		fmt.Printf("(%v) gen arg using helper return value\n", rd)
		a, ok = p.genRandBpfHelperCall(r, call, arg)
	}
	if !ok && r.nOutOf(1, 2) {
		fmt.Printf("(%v) gen arg using ctx access\n", rd)
		a, ok = p.genRandBpfCtxAccess(r, call, arg)
	}
	if !ok {
		fmt.Printf("(%v) gen arg directly\n", rd)
		a, ok = p.genRandDirectAccess(r, call, arg)
	}
	if !ok {
		return false
	}
	fmt.Printf("(%v) gen arg v%v\n", r, ok, p.VarId)

	if argType == "ARG_CONST_SIZE" || argType == "ARG_CONST_SIZE_OR_ZERO" {
		a.Umax = int64(call.StackVarSize) //XXX check if this handle multiple mem size pairs
	}

	// Adding a predicate other than the referenced object can produce paths that may leak references
	// XXX Is it possible to achieve so without leaking ref?
	if call.isRefReleaseCall() != -1 && arg != 0 {
		//if a.IsNotNull && a.CanBeNull {
		if !a.IsNotNull && !a.CanBeNull {
			return false
		}
	}

	call.Args[arg] = a
	return true
}

//XXX add mem size constraints
func (p *BpfProg) genCompatibleRegTypes(call *BpfCall, arg int) ([]RegType, string) {
	argType := call.Helper.Args[arg]
	regTypes := compatibleRegType[argType]
	if argType == "ARG_PTR_TO_UNINIT_MAP_VALUE" || argType == "ARG_PTR_TO_UNINIT_MEM" {
		for i, t := range regTypes {
			if !t.CheckAccess(p, call.Helper, true) {
				regTypes = append(regTypes[0:i], regTypes[i+1:]...)
			}
		}
	}
	if !checkPktAccess(p, call.Helper, false) { //verbose_5053
		for i, t := range regTypes {
			if t.String() == "PTR_TO_PACKET" || t.String() == "PTR_TO_PACKET_META" {
				regTypes = append(regTypes[0:i], regTypes[i+1:]...)
			}
		}
	}

	btfId := ""
	if argType == "ARG_PTR_TO_BTF_ID" {
		btfId = call.Helper.ArgBtfIds[0] //XXX helpers have only one at most now
	} else if argType == "ARG_PTR_TO_BTF_ID_SOCK_COMMON" {
		btfId = "struct sock_common"
	}
	return regTypes, btfId
}

func (p *BpfProg) genRandDirectAccess(r *randGen, call *BpfCall, arg int) (*BpfArg, bool) {
	compatRegTypes, _ := p.genCompatibleRegTypes(call, arg)
	for i := 0; i < 5; i++ {
		rt := compatRegTypes[r.Intn(len(compatRegTypes))]
		a := rt.Generate(p, r, call, arg)
		if a != nil {
			fmt.Printf("(%v) gen arg using %v directly\n", rd, rt.String())
			return a, true
		}
	}
	return nil, false
}

func (p *BpfProg) genRandBpfCtxAccess(r *randGen, call *BpfCall, arg int) (*BpfArg, bool) {
	compatRegTypes, _ := p.genCompatibleRegTypes(call, arg)
	for i := 0; i < 5; i++ {
		a := NewBpfArg(call.Helper, arg)
		rt := compatRegTypes[r.Intn(len(compatRegTypes))].String()
		ranges, ok := p.pt.ctxAccess.regTypeMap[rt]
		if !ok {
			ranges, ok = p.pt.ctxAccess.regTypeMap[rt+"_OR_NULL"]//XXX improve arg OR_NULL compatibility check/propagation
		}

		if !ok {
			continue
		}

		var ctxStruct *StructDef
		if len(p.pt.User) > 6 && p.pt.User[0:6] == "struct" {
			ctxStruct = ctxStructsMap[p.pt.User[7:len(p.pt.User)]]
			readAccess := p.pt.ctxAccess.accesses[ctxStruct.fieldIdx(ranges[0][2])*2].canRead
			writeAccess := p.pt.ctxAccess.accesses[ctxStruct.fieldIdx(ranges[0][2])*2+1].canWrite
			if !readAccess && !writeAccess {
				continue
			}
		} else {
			var defaultAccess BpfCtxAccessAttr
			for _, access := range p.pt.ctxAccess.accesses {
				if access.rangeInCtx[0] == "default" {
					defaultAccess = access
				}
			}
			if !defaultAccess.canRead && !defaultAccess.canWrite {
				continue
			}
		}

		typ := "void *"
		if rt == "PTR_TO_SOCK_COMMON" {
			typ = "struct sock_common*"
		}

		field := ranges[0][2]
		if v, ok := p.CtxVars[field]; ok {
			a.Name = v
		} else {
			a.Name = fmt.Sprintf("v%d", p.VarId)
			p.VarId += 1
			p.CtxVars[field] = a.Name
			p.CtxTypes[field] = typ
		}
		if rt == "PTR_TO_PACKET_META" {
			if _, ok := p.CtxVars["data"]; !ok {
				a1 := fmt.Sprintf("v%d", p.VarId)
				p.VarId += 1
				p.CtxVars["data"] = a1
				p.CtxTypes["data"] = typ
			}
			argType := call.Helper.Args[arg]
			a.IsPktMetaAccess = true
			if argType == "ARG_PTR_TO_MAP_KEY" {
				if call.ArgMap != nil && call.ArgMap.Key != nil {
					//a.AccessSize = call.ArgMap.Key.Size
					a.AccessSize = roundUp(call.ArgMap.Key.Size, 8) //XXX need to round up key size?
				}
			}
			if argType == "ARG_PTR_TO_MAP_VALUE" || argType == "ARG_PTR_TO_MAP_VALUE_OR_NULL" || argType == "ARG_PTR_TO_UNINIT_MAP_VALUE" {
				if call.ArgMap != nil && call.ArgMap.Val != nil {
					//a.AccessSize = call.ArgMap.Val.Size
					a.AccessSize = roundUp(call.ArgMap.Val.Size, 8)
				}
			}
			if argType == "ARG_PTR_TO_MEM" || argType == "ARG_PTR_TO_MEM_OR_NULL" || argType == "ARG_PTR_TO_UNINIT_MEM" {
				size := r.Intn(128)//XXX determine max
				a.AccessSize = size
				call.StackVarSize = size
			}
			if argType == "ARG_PTR_TO_INT" {
				a.AccessSize = 4
			}
			if argType == "ARG_PTR_TO_LONG" {
				a.AccessSize = 8
			}
//			a.AccessSize = call.Hint.RetAccessSize
		}
		if rt == "PTR_TO_PACKET" {
			if _, ok := p.CtxVars["data_end"]; !ok {
				a1 := fmt.Sprintf("v%d", p.VarId)
				p.VarId += 1
				p.CtxVars["data_end"] = a1
				p.CtxTypes["data_end"] = typ
			}
			argType := call.Helper.Args[arg]
			a.IsPktAccess = true
			if argType == "ARG_PTR_TO_MAP_KEY" {
				if call.ArgMap != nil && call.ArgMap.Key != nil {
					//a.AccessSize = call.ArgMap.Key.Size
					a.AccessSize = roundUp(call.ArgMap.Key.Size, 8) //XXX need to round up key size?
				}
			}
			if argType == "ARG_PTR_TO_MAP_VALUE" || argType == "ARG_PTR_TO_MAP_VALUE_OR_NULL" || argType == "ARG_PTR_TO_UNINIT_MAP_VALUE" {
				if call.ArgMap != nil && call.ArgMap.Val != nil {
					//a.AccessSize = call.ArgMap.Val.Size
					a.AccessSize = roundUp(call.ArgMap.Val.Size, 8)
				}
			}
			if argType == "ARG_PTR_TO_MEM" || argType == "ARG_PTR_TO_MEM_OR_NULL" || argType == "ARG_PTR_TO_UNINIT_MEM" {
				size := r.Intn(128)//XXX determine max
				a.AccessSize = size
				call.StackVarSize = size
			}
			if argType == "ARG_PTR_TO_INT" {
				a.AccessSize = 4
			}
			if argType == "ARG_PTR_TO_LONG" {
				a.AccessSize = 8
			}
//			a.AccessSize = call.Hint.RetAccessSize
		}
		return a, true
	}
	return nil, false
}


//RET_INTEGER,                    /* function returns integer */
//RET_VOID,                       /* function doesn't return anything */
//RET_PTR_TO_MAP_VALUE,           /* returns a pointer to map elem value */
//RET_PTR_TO_MAP_VALUE_OR_NULL,   /* returns a pointer to map elem value or NULL */
//RET_PTR_TO_SOCKET_OR_NULL,      /* returns a pointer to a socket or NULL */
//RET_PTR_TO_TCP_SOCK_OR_NULL,    /* returns a pointer to a tcp_sock or NULL */
//RET_PTR_TO_SOCK_COMMON_OR_NULL, /* returns a pointer to a sock_common or NULL */
//RET_PTR_TO_ALLOC_MEM_OR_NULL,   /* returns a pointer to dynamically allocated memory or NULL */
//RET_PTR_TO_BTF_ID_OR_NULL,      /* returns a pointer to a btf_id or NULL */
//RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL, /* returns a pointer to a valid memory or a btf_id or NULL */
//RET_PTR_TO_MEM_OR_BTF_ID,       /* returns a pointer to a valid memory or a btf_id */
//RET_PTR_TO_BTF_ID,              /* returns a pointer to a btf_id */
func bpfRetType(call *BpfCall) string {
	if call.Helper.Ret == "RET_INTEGER" {
		return "uint64_t"
	} else if call.Helper.Ret == "RET_PTR_TO_MAP_VALUE" ||
		call.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
		if call.ArgMap.Val == nil {
			return "void *"
		} else {
			return fmt.Sprintf("%v*", call.ArgMap.Val.Name)
		}
	} else if call.Helper.Ret == "RET_PTR_TO_BTF_ID_OR_NULL" ||
		call.Helper.Ret == "RET_PTR_TO_BTF_ID" {
		return fmt.Sprintf("%v*", call.Helper.RetBtfId)
	} else if call.Helper.Ret == "RET_PTR_TO_ALLOC_MEM_OR_NULL" ||
		call.Helper.Ret == "RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL" ||
		call.Helper.Ret == "RET_PTR_TO_MEM_OR_BTF_ID" {
		return "void *"
	} else if call.Helper.Ret == "RET_PTR_TO_TCP_SOCK_OR_NULL" ||
		call.Helper.Ret == "RET_PTR_TO_SOCKET_OR_NULL" ||
		call.Helper.Ret == "RET_PTR_TO_SOCK_COMMON_OR_NULL" {
		return "struct bpf_sock*"
	} else {
		return ""
	}
}

// recursion depth of genBpfHelperCall
var rd int

func (p *BpfProg) getBpfHelpers(enums []BpfHelperEnum) ([]*BpfHelper) {
	var helpers []*BpfHelper
	for _, helper := range p.pt.Helpers {
		for _, enum := range enums {
			if helper.Enum == enum {
				helpers = append(helpers, helper)
			}
		}
	}
	return helpers
}

func (p *BpfProg) genBpfHelperCall(r *randGen, helper *BpfHelper, hint *BpfCallGenHint, prepend bool) (*BpfCall, bool) {
	rd += 1
	if rd > 100 {
		fmt.Printf("(%v) failed to gen helper call. Tried generating helper call resursively too hard\n", rd)
		return nil, false
	}

	preferredMapName := "nil"
	if hint.PreferredMap != nil {
		preferredMapName = hint.PreferredMap.Name
	}
	fmt.Printf("(%v) gen call[%v] hint: ArgHints=%v, RetAccessSize=%v, IsRetAccessRaw=%v, PreferredMap=%v\n",
		rd, len(p.Calls), hint.ArgHints, hint.RetAccessSize, hint.IsRetAccessRaw, preferredMapName)

	call := NewBpfCall(helper, hint)
	attempt := 0
	for i := 0; i < len(helper.Args); {
		fmt.Printf("(%v) attempt=%v\n", rd, attempt)
		if p.genBpfHelperCallArg(r, call, i) {
			attempt = 0
			i++
		} else if attempt += 1; attempt > 50 {
			fmt.Printf("failed to gen arg[%d] for %v\n", i , helper.Enum)
			return nil, false
		}
	}

	// Do not acquire references if the program has no helper to release them
	if call.isRefAcquireCall() == 1 && len(p.getBpfHelpers([]BpfHelperEnum{BPF_FUNC_sk_release})) == 0 {
		return nil, false
	}

	if typ := bpfRetType(call); typ != "" {
		call.RetType = typ
	}
	call.Ret = fmt.Sprintf("v%v", p.VarId)
	p.VarId += 1
	if prepend {
		p.Calls = append([]*BpfCall{call}, p.Calls...)
	} else {
		p.Calls = append(p.Calls, call)
	}
	rd -= 1

	return call, true
}

var retToRegTypeMap = map[string]map[string]bool{
	"RET_INTEGER":                      map[string]bool{"SCALAR_VALUE": true},
	"RET_VOID":                         map[string]bool{"NOT_INIT": true},
	"RET_PTR_TO_MAP_VALUE":             map[string]bool{"PTR_TO_MAP_VALUE": true},
//	"RET_PTR_TO_MAP_VALUE_OR_NULL":     map[string]bool{"PTR_TO_MAP_VALUE": true},
	"RET_PTR_TO_MAP_VALUE_OR_NULL":     map[string]bool{"PTR_TO_MAP_VALUE": true, "PTR_TO_XDP_SOCK": true, "PTR_TO_SOCKET": true},
	"RET_PTR_TO_SOCKET_OR_NULL":        map[string]bool{"PTR_TO_SOCKET": true},
	"RET_PTR_TO_TCP_SOCK_OR_NULL":      map[string]bool{"PTR_TO_TCP_SOCK": true},
	"RET_PTR_TO_SOCK_COMMON_OR_NULL":   map[string]bool{"PTR_TO_SOCK_COMMON": true},
	"RET_PTR_TO_ALLOC_MEM_OR_NULL":     map[string]bool{"PTR_TO_ALLOC_MEM": true},
	"RET_PTR_TO_BTF_ID_OR_NULL":        map[string]bool{"PTR_TO_BTF_ID": true},
	"RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL": map[string]bool{"PTR_TO_MEM": true, "PTR_TO_BTF_ID":true},
	"RET_PTR_TO_MEM_OR_BTF_ID":         map[string]bool{"PTR_TO_MEM": true, "PTR_TO_BTF_ID":true},
	"RET_PTR_TO_BTF_ID":                map[string]bool{"PTR_TO_BTF_ID": true},
}

func helperCanReturn(helper *BpfHelper, reg RegType, btfId string) bool {
	if retToRegTypeMap[helper.Ret][reg.String()] {
		if btfId != "" {
			if helper.Ret == "RET_PTR_TO_BTF_ID_OR_NULL" || helper.Ret == "RET_PTR_TO_BTF_ID" {
				return btfId == helper.RetBtfId
			}
			if helper.Ret == "RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL" || helper.Ret == "RET_PTR_TO_MEM_OR_BTF_ID" {
				//XXX gen random ksym
				return false
			}
		}
		return true
	}
	return false
}

func genHint(r *randGen, producer *BpfHelper, consumer *BpfCall, arg int) *BpfCallGenHint {
	hint := newBpfCallGenHint(nil)
	consumerArg := consumer.Helper.Args[arg]

	if (consumerArg == "ARG_PTR_TO_SOCK_COMMON" || consumerArg == "ARG_PTR_TO_BTF_ID_SOCK_COMMON") {
		if producer.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
			if r.nOutOf(1, 2) {
				hint.ArgHints[HintGenXdpSockMap] = true
			} else {
				hint.ArgHints[HintGenSockMap] = true
			}
		}
	}
	if (consumerArg == "ARG_PTR_TO_SOCKET" || consumerArg == "ARG_PTR_TO_SOCKET_OR_NULL") {
		if producer.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
			hint.ArgHints[HintGenSockMap] = true
		}
	}
	if consumerArg == "ARG_PTR_TO_SPIN_LOCK" {
		hint.ArgHints[HintGenSpinlock] = true
	}
	if consumerArg == "ARG_PTR_TO_TIMER" {
		hint.ArgHints[HintGenTimer] = true
	}
	if consumerArg == "ARG_PTR_TO_CONST_STR" {
		hint.ArgHints[HintGenConstStr] = true
	}

	if consumerArg == "ARG_PTR_TO_MAP_KEY" {
		if consumer.ArgMap != nil && consumer.ArgMap.Key != nil {
			hint.RetAccessSize = roundUp(consumer.ArgMap.Key.Size, 8)
			//hint.RetAccessSize = consumer.ArgMap.Key.Size
		}
	}
	if consumerArg == "ARG_PTR_TO_MAP_VALUE" || consumerArg == "ARG_PTR_TO_MAP_VALUE_OR_NULL" || consumerArg == "ARG_PTR_TO_UNINIT_MAP_VALUE" {
		if consumer.ArgMap != nil && consumer.ArgMap.Val != nil {
			hint.RetAccessSize = roundUp(consumer.ArgMap.Val.Size, 8)
			//hint.RetAccessSize = consumer.ArgMap.Val.Size
		}
	}

	if consumerArg == "ARG_PTR_TO_UNINIT_MAP_VALUE" || consumerArg == "ARG_PTR_TO_UNINIT_MEM"  {
		hint.IsRetAccessRaw = true
	}

	return hint
}

/* Generate a random helper call that returns values compatible with *arg*-th argument of *call* */
func (p *BpfProg) genRandBpfHelperCall(r *randGen, call *BpfCall, arg int) (*BpfArg, bool) {
	a := NewBpfArg(call.Helper, arg)
	var compatHelpers []*BpfHelper
	compatRegTypes, btfId := p.genCompatibleRegTypes(call, arg)
	for _, helper := range p.pt.Helpers {
		for _, regType := range compatRegTypes {
			if !helperCanReturn(helper, regType, btfId) {
				continue
			}
			if call.Helper.Args[arg] == "ARG_CONST_ALLOC_SIZE_OR_ZERO" && regType.String() == "SCALAR_VALUE" { //5228
				continue
			}
			compatHelpers = append(compatHelpers, helper)
			fmt.Printf("(%v) compatible helper: %v\n", rd, helper.Enum)
		}
	}

	if len(compatHelpers) == 0 {
		return nil, false
	}

	helper := compatHelpers[r.Intn(len(compatHelpers))]
	hint := genHint(r, helper, call, arg)
	prodCall, ok := p.genBpfHelperCall(r, helper, hint, false)
	if ok {
		argType := call.Helper.Args[arg]
		retStruct := ""
		if start := strings.Index(prodCall.RetType, "struct_"); start != -1 {
			if end := strings.Index(prodCall.RetType, "*"); end != -1 {
				retStruct = prodCall.RetType[start:end]
			}
		}
		if argType == "ARG_PTR_TO_SPIN_LOCK" {
			mi := findMember(p, retStruct, "struct bpf_spin_lock")
			a.Name = fmt.Sprintf("&%v->e%v", prodCall.Ret, mi)
		} else if argType == "ARG_PTR_TO_TIMER" {
			call.ArgMap = prodCall.ArgMap
			mi := findMember(p, retStruct, "struct bpf_timer")
			a.Name = fmt.Sprintf("&%v->e%v", prodCall.Ret, mi)
		} else if argType == "ARG_PTR_TO_CONST_STR" {
			mi := findMember(p, retStruct, "char [8]")
			a.Name = fmt.Sprintf("%v->e%v", prodCall.Ret, mi)
		} else if (prodCall.Helper.Ret == "RET_PTR_TO_MAP_VALUE" || prodCall.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL") &&
			prodCall.ArgMap.Val != nil && len(prodCall.ArgMap.Val.FieldTypes) >= 2 {
			var members []int
			for mi, mt := range prodCall.ArgMap.Val.FieldTypes {
				if mt != "struct bpf_spin_lock" && mt != "struct bpf_timer" &&
					(prodCall.ArgMap.Val.Size - prodCall.ArgMap.Val.offsetOfMember(mi) >= prodCall.Hint.RetAccessSize) {
					members = append(members, mi)
				}
			}
			if len(members) == 0 {
				fmt.Printf("(%v) failed to find a valid offset in %v\n", rd, prodCall.ArgMap.Name)
				ok = false
			} else {
				a.Name = fmt.Sprintf("&%v->e%v", prodCall.Ret, members[r.Intn(len(members))])
				a.CanBeNull = false //XXX add this in case it is passed to ANYTHING
			}
		} else {
			a.Name = prodCall.Ret
		}

		if ok {
			if prodCall.Helper.Ret == "RET_INTEGER" || prodCall.Helper.Ret == "RET_VOID" ||
				prodCall.Helper.Ret == "RET_PTR_TO_MAP_VALUE" ||
				prodCall.Helper.Ret == "RET_PTR_TO_MEM_OR_BTF_ID" ||
				prodCall.Helper.Ret == "RET_PTR_TO_BTF_ID" {
				if !a.CanBeNull {
					a.IsNotNull = true
				}
			}

			//3149, 3155
			if prodCall.Helper.Ret == "RET_PTR_TO_MAP_VALUE" || prodCall.Helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
				if argType == "ARG_PTR_TO_UNINIT_MAP_VALUE" || argType == "ARG_PTR_TO_UNINIT_MEM"  {
					prodCall.ArgMap.removeFlag("BPF_F_RDONLY_PROG")
				} else {
					prodCall.ArgMap.removeFlag("BPF_F_WRONLY_PROG")
				}
			}
		}
	}
	return a, ok
}

func (brf *BpfRuntimeFuzzer) GenBpfProg(r *randGen, opt BrfGenProgOpt) (*BpfProg, bool) {
	pt := brf.progTypeMap[BpfProgTypeEnum(r.Intn(int(BPF_PROG_TYPE_TRACING))+1)]
	helper := pt.Helpers[r.Intn(len(pt.Helpers))]
	p := NewBpfProg(pt, r, opt)

	fmt.Printf("gen prog %v %v\n", pt.Name, helper.Enum)
	rd = 0
	hint := newBpfCallGenHint(nil)
	_, ok := p.genBpfHelperCall(r, helper, hint, false)
	return p, ok
}

func (brf *BpfRuntimeFuzzer) MutBpfProg(r *randGen, p *BpfProg, opt BrfGenProgOpt) bool {
	var calls []*BpfCall
	for _, c := range p.Calls {
		if len(c.Args) > 0 {
			calls = append(calls, c)
		}
	}

	if len(calls) == 0 {
		return false
	}

	call := calls[r.Intn(len(calls))]
	arg := r.Intn(len(call.Args))
	return p.genBpfHelperCallArg(r, call, arg)
}

type ObjRef struct {
	vars     []string
	objMap   *BpfMap
	typ      int
	count    int
	calls    []*BpfCall
}

func (call *BpfCall) isRefAcquireCall() int {
	refType := -1
	if call.Helper.Enum == BPF_FUNC_sk_lookup_tcp || call.Helper.Enum == BPF_FUNC_sk_lookup_udp || call.Helper.Enum == BPF_FUNC_skc_lookup_tcp ||
		(call.Helper.Enum == BPF_FUNC_map_lookup_elem && (call.ArgMap.Type == "BPF_MAP_TYPE_SOCKMAP" || call.ArgMap.Type == "BPF_MAP_TYPE_SOCKHASH")) {
		refType = 1
	}
	if call.Helper.Enum == BPF_FUNC_ringbuf_reserve {
		refType = 2
	}
	return refType
}

func (call *BpfCall) isRefReleaseCall() int {
	refType := -1
	if call.Helper.Enum == BPF_FUNC_sk_release {
		refType = 1
	}
	if call.Helper.Enum == BPF_FUNC_ringbuf_submit || call.Helper.Enum == BPF_FUNC_ringbuf_discard {
		refType = 2
	}
	return refType
}

func (call *BpfCall) isRefPropagateCall() int {
	refType := -1
	if call.Helper.Enum == BPF_FUNC_tcp_sock || call.Helper.Enum == BPF_FUNC_sk_fullsock ||
		call.Helper.Enum == BPF_FUNC_skc_to_tcp_sock || call.Helper.Enum == BPF_FUNC_skc_to_tcp6_sock ||
		call.Helper.Enum == BPF_FUNC_skc_to_udp6_sock || call.Helper.Enum == BPF_FUNC_skc_to_tcp_timewait_sock ||
		call.Helper.Enum == BPF_FUNC_skc_to_tcp_request_sock {
		refType = 1
	}
	return refType
}

func (p *BpfProg) FixRef(r *randGen) {
	objRefMap := make(map[string]*ObjRef)
	for i, call := range p.Calls {
		if refType := call.isRefAcquireCall(); refType != -1 {
			v := call.Ret
			if _, ok := objRefMap[v]; !ok {
				objRefMap[v] = &ObjRef{vars: []string{v}, objMap: call.ArgMap, typ: refType, count: 0, calls: []*BpfCall{call}}
			}
			objRefMap[v].count += 1
			fmt.Printf("ref(%v:%v) acquired by call #%v %v\n", v, objRefMap[v].count, i, call.Helper.Enum)
		}
		if refType := call.isRefReleaseCall(); refType != -1 {
			v := call.Args[0].Name
			if _, ok := objRefMap[v]; !ok {
				objRefMap[v] = &ObjRef{vars: []string{v}, objMap: call.ArgMap, typ: refType, count: 0, calls: []*BpfCall{call}}
			}
			objRefMap[v].count -= 1
			fmt.Printf("ref(%v:%v) released by call #%v %v\n", v, objRefMap[v].count, i, call.Helper.Enum)
		}
		if refType := call.isRefPropagateCall(); refType != -1 {
			v := call.Args[0].Name
			vp := call.Ret
			if ref, ok := objRefMap[v]; ok {
				ref.calls = append(ref.calls, call)
				ref.vars = append(ref.vars, vp)
				objRefMap[vp] = ref
				fmt.Printf("ref(%v:%v) propagated by call #%v %v\n", v, objRefMap[v].count, i, call.Helper.Enum)
			} else {
				fmt.Printf("ref(%v:0) propagated by call #%v %v\n", v, i, call.Helper.Enum)
			}
		}
	}

	for _, ref := range objRefMap {
		if ref.count < 0 {
			// Add a ref-acquire helper
			if ref.typ == 1 {
				helpers := p.getBpfHelpers([]BpfHelperEnum{BPF_FUNC_sk_lookup_tcp, BPF_FUNC_sk_lookup_udp, BPF_FUNC_skc_lookup_tcp, BPF_FUNC_map_lookup_elem})
				if len(helpers) > 0 {
					helper := helpers[r.Intn(len(helpers))]
					hint := newBpfCallGenHint(ref.objMap)
					if prodCall, ok := p.genBpfHelperCall(r, helper, hint, true); ok {//XXX change to ENUM append, prepend, random
						ref.calls[0].Args[0].Name = prodCall.Ret
						fmt.Printf("ref: fix releasing invalid ref(%v:%v) by adding %v\n", ref.vars[0], ref.count, helper.Enum)
					} else {
						fmt.Printf("ref: fix releasing invalid ref(%v:%v) failed since no helper can acquire the reference\n", ref.vars[0], ref.count)
					}
				}
			}
			if ref.typ == 2 {
				helpers := p.getBpfHelpers([]BpfHelperEnum{BPF_FUNC_ringbuf_reserve})
				if len(helpers) > 0 {
					helper := helpers[r.Intn(len(helpers))]
					hint := newBpfCallGenHint(ref.objMap)
					if prodCall, ok := p.genBpfHelperCall(r, helper, hint, true); ok {
						ref.calls[0].Args[0].Name = prodCall.Ret
						fmt.Printf("ref: fix releasing invalid ref(%v:%v) by adding %v\n", ref.vars[0], ref.count, helper.Enum)
					} else {
						fmt.Printf("ref: fix releasing invalid ref(%v:%v) failed since no helper can acquire the reference\n", ref.vars[0], ref.count)
					}
				}
			}
		}
		if ref.count > 0 {
			// Add a ref-release helper
			if ref.typ == 1 {
				helpers := p.getBpfHelpers([]BpfHelperEnum{BPF_FUNC_sk_release})
				if len(helpers) > 0 {
					helper := helpers[r.Intn(len(helpers))]
					hint := newBpfCallGenHint(ref.objMap)
					//p.genBpfHelperCall(r, h, hint, false)
					call := NewBpfCall(helper, hint)
					a0 := NewBpfArg(helper, 0)
					a0.Name = ref.vars[r.Intn(len(ref.vars))]
					call.Args[0] = a0
					ref.calls[0].PostCalls = append(ref.calls[0].PostCalls, call)
					//p.Calls = append(p.Calls, call)
					ref.count = 0
					fmt.Printf("ref: fixing leaking ref(%v:%v) by adding %v\n", ref.vars[0], ref.count, helper.Enum)
				} else {
					fmt.Printf("ref: fixing leaking ref(%v:%v) failed since no helper can release the reference\n", ref.vars[0], ref.count)
				}
			}
			if ref.typ == 2 {
				helpers := p.getBpfHelpers([]BpfHelperEnum{BPF_FUNC_ringbuf_submit, BPF_FUNC_ringbuf_discard})
				if len(helpers) > 0 {
					helper := helpers[r.Intn(len(helpers))]
					hint := newBpfCallGenHint(ref.objMap)
					//p.genBpfHelperCall(r, h, hint, false)
					call := NewBpfCall(helper, hint)
					a0 := NewBpfArg(helper, 0)
					a0.Name = ref.vars[r.Intn(len(ref.vars))]
					call.Args[0] = a0
					a1 := NewBpfArg(helper, 1)
					a1.Name = "0"
					a1.IsNotNull = true
					call.Args[1] = a1
					p.Calls = append(p.Calls, call)
					ref.count = 0
					fmt.Printf("ref: fixing leaking ref(%v:%v) by adding %v\n", ref.vars[0], ref.count, helper.Enum)
				} else {
					fmt.Printf("ref: fixing leaking ref(%v:%v) failed since no helper can release the reference\n", ref.vars[0], ref.count)
				}
			}
		}
	}
}

func (p *BpfProg) FixSpinLock(r *randGen) {
	lockHeld := ""
	for i, call := range p.Calls {
		if call.Helper.Enum == BPF_FUNC_spin_unlock {
			if lockHeld == "" {
				if helper := p.pt.getHelper(BPF_FUNC_spin_lock); helper != nil {
					hint := newBpfCallGenHint(nil)
					call := NewBpfCall(helper, hint)
					a0 := NewBpfArg(helper, 0)
					a0.Name = p.Calls[i].Args[0].Name
					call.Args[0] = a0
					lockHeld = a0.Name
					p.Calls = append(p.Calls[:i+1], p.Calls[i:]...)
					p.Calls[i] = call
				} else {
					fmt.Printf("spinlock: fixing spinlock failed since no helper can lock the spinlock\n")
					break
				}
			} else {
				if lockHeld == call.Args[0].Name {
					lockHeld = ""
				} else {
					fmt.Printf("spinlock: fixing a mismatch spin_unlock\n")
					call.Args[0].Name = lockHeld
				}
			}
		}
		if call.Helper.Enum == BPF_FUNC_spin_lock {
			if i == len(p.Calls)-1 || p.Calls[i+1].Helper.Enum != BPF_FUNC_spin_unlock {
				if helper := p.pt.getHelper(BPF_FUNC_spin_unlock); helper != nil {
					hint := newBpfCallGenHint(nil)
					call := NewBpfCall(helper, hint)
					a0 := NewBpfArg(helper, 0)
					a0.Name = p.Calls[i].Args[0].Name
					call.Args[0] = a0
					lockHeld = a0.Name
					p.Calls = append(p.Calls[:i+1], p.Calls[i:]...)
					p.Calls[i+1] = call
				} else {
					fmt.Printf("spinlock: fixing spinlock failed since no helper can unlock the spinlock\n")
					break
				}
			} else {
				lockHeld = call.Args[0].Name
			}
		}
	}
}

//417-program exit
func genRandReturnVal(r *randGen, e BpfProgTypeEnum) int {
	retVal := 0
	switch(e) {
		case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
			//retVal = r.Intn(4) //(0,3)
			retVal = 1
		case BPF_PROG_TYPE_CGROUP_SKB:
			//retVal = r.Intn(4) //(0,3)
			retVal = r.Intn(2) //(0,1)
		case BPF_PROG_TYPE_CGROUP_SOCK:
			retVal = r.Intn(2) //(0,1)
		case BPF_PROG_TYPE_SOCK_OPS:
			retVal = r.Intn(2) //(0,1)
		case BPF_PROG_TYPE_CGROUP_DEVICE:
			retVal = r.Intn(2) //(0,1)
		case BPF_PROG_TYPE_CGROUP_SYSCTL:
			retVal = r.Intn(2) //(0,1)
		case BPF_PROG_TYPE_CGROUP_SOCKOPT:
			retVal = r.Intn(2) //(0,1)
		case BPF_PROG_TYPE_RAW_TRACEPOINT:
			retVal = 0
		case BPF_PROG_TYPE_TRACING:
			retVal = 0
		case BPF_PROG_TYPE_SK_LOOKUP:
			retVal = r.Intn(2) //(SK_DROP, SK_PASS)
		default:
			retVal = r.Intn(1<<32)
	}
	return retVal
}

func (p *BpfProg) genCSource() string {
	s := new(bytes.Buffer)

	fmt.Fprintf(s, "#include \"vmlinux.h\"\n")
	fmt.Fprintf(s, "#include <bpf/bpf_helpers.h>\n\n")

	for _, t := range p.Structs {
		if !t.IsStruct {
			continue
		}

		fmt.Fprintf(s, "typedef struct %v {\n", t.Name)
		for i, m := range t.FieldTypes {
			if m == "char [8]" {
				fmt.Fprintf(s, "    char e%v[8];\n", i)
			} else {
				fmt.Fprintf(s, "    %v e%v;\n", m, i)
			}
		}
		fmt.Fprintf(s, "} %v;\n\n", t.Name)
	}

	for v, t := range p.Externs {
		fmt.Fprintf(s, "extern const %s %s __ksym;\n\n", t, v)
	}

	for _, m := range p.Maps {
		fmt.Fprintf(s, "%s\n", m.String())
	}

	fmt.Fprintf(s, "%s", p.SecStr)
	fmt.Fprintf(s, "int func(%s *ctx) {\n", p.pt.User)
	for field, v := range p.CtxVars {
		fmt.Fprintf(s, "	%s %s = ctx->%s;\n", p.CtxTypes[field], v, field)
	}
	for i, call := range p.Calls {
		for j, arg := range call.Args {
			if arg == nil {
				fmt.Printf("debug %v %v %v nil\n", i, call.Helper.Enum, j)
			}
			if arg.Prepare != "" {
				fmt.Fprintf(s, "%s", arg.Prepare)
			}
		}
		if call.RetType != "" {
			fmt.Fprintf(s, "	%s %s = 0;\n", call.RetType, call.Ret) // XXX see if compiler stop optimize out null check
		}

		// Check arguments before calling a helper
		indent := ""
		constraints := call.getArgConstraints(p)
		if len(constraints) != 0 {
			fmt.Fprintf(s, "	if (")
			for i, c := range constraints {
				fmt.Fprintf(s, "%v", c)
				if i < len(constraints)-1 {
					fmt.Fprintf(s, " && ")
				}
			}
			fmt.Fprintf(s, ") {\n")
			indent = "	"
		}

		if call.RetType != "" {
			fmt.Fprintf(s, "%s	%s = %s(", indent, call.Ret, call.Helper.Uname)
		} else {
			fmt.Fprintf(s, "%s	%s(", indent, call.Helper.Uname)
		}
		for i, arg := range call.Args {
			fmt.Fprintf(s, "%v", arg.Name)
			if i < len(call.Args)-1 {
				fmt.Fprintf(s, ", ")
			}
		}
		fmt.Fprintf(s, ");\n")

		for _, pcall := range call.PostCalls {
			fmt.Fprintf(s, "%s	%s(", indent, pcall.Helper.Uname)
			for i, arg := range pcall.Args {
				fmt.Fprintf(s, "%v", arg.Name)
				if i < len(pcall.Args)-1 {
					fmt.Fprintf(s, ", ")
				}
			}
			fmt.Fprintf(s, ");\n")
		}

		if len(constraints) != 0 {
			fmt.Fprintf(s, "	}\n")
		}
	}

	fmt.Fprintf(s, "	return %v;\n", p.RetVal)
	fmt.Fprintf(s, "}\n\n")

	fmt.Fprintf(s, "char _license[] SEC(\"license\") = \"GPL\";\n")

	fmt.Printf("\n%v\n", s)

	return s.String()
}

