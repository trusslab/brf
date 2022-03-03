package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	//"time"

	"github.com/google/syzkaller/pkg/bcc"
	//"github.com/iovisor/gobpf/bcc"
	//"github.com/google/syzkaller/prog"
)


// nOutOf returns true n out of outOf times.
func nOutOf(n, outOf int) bool {
	if n <= 0 || n >= outOf {
		panic("bad probability")
	}
	v := rand.Intn(outOf)
	return v < n
}

type PathLinePair struct {
	Path string
	Line int
}

type BpfProgTypeDef struct {
	Name       string
	User       string
	Kern       string
	Enum       string
	Helpers    []*BpfHelperFunc
	ctxAccess  *BpfCtxAccess
//	ctx        Arg
}

func NewBpfProgTypeDef() *BpfProgTypeDef {
	bpfProgType := new(BpfProgTypeDef)
	return bpfProgType
}

type BpfHelperFunc struct {
	Name     string
	Proto    string
	Args     []string
	Ret      string
//	args     []*RegType
//	ret      *RegType
	GplOnly  bool
}

type BpfMap struct {
	name string
	key  string
	ent  string
	size int
}

type BpfCall struct {
	helper  *BpfHelperFunc
	prepare []string
	args    []string
	ret     string
	retType string
}

type BpfProgState struct {
	pt       *BpfProgTypeDef
	varId    int
	maps     []*BpfMap
	calls    []*BpfCall
	misc     *bytes.Buffer
//	structs  []prog.Type
	brf      *BpfRuntimeFuzzer
}

func NewBpfProgState(brf *BpfRuntimeFuzzer, pt *BpfProgTypeDef) *BpfProgState {
	newProgState := new(BpfProgState)
	newProgState.brf = brf
	newProgState.pt = pt
	newProgState.misc = new(bytes.Buffer)
	return newProgState
}

func (s *BpfProgState) AddMap(name string, key string, ent string, size int) {
	newMap := new(BpfMap)
	newMap.name = name
	newMap.key = key
	newMap.ent = ent
	newMap.size = size
	s.maps = append(s.maps, newMap)
}

func NewBpfCall(helper *BpfHelperFunc) *BpfCall {
	newCall := new(BpfCall)
	newCall.helper = helper
	newCall.args = make([]string, len(helper.Args))
	newCall.prepare = make([]string, len(helper.Args))
	return newCall
}

func NewBpfFuncProto(attr map[string]string) *BpfHelperFunc {
	bfp := new(BpfHelperFunc)
	bfp.Proto = attr["proto"]
	bfp.Name = attr["func"]
	bfp.Ret = attr["ret_type"]
	bfp.GplOnly = attr["gpl_only"] == "true"
	for i := 1; i <= 5; i++ {
		argName := fmt.Sprintf("arg%d_type", i)
		if argType, ok := attr[argName]; ok {
			bfp.Args = append(bfp.Args, argType)
		}
	}
	return bfp
}

type RegType interface {
	String() string
	Generate(s *BpfProgState) (string, string)
}

type ScalarValRegType struct {
}

func (t ScalarValRegType) String() string {
	return "SCALAR_VALUE"
}

func (t ScalarValRegType) Generate(s *BpfProgState) (string, string) {
	argName := fmt.Sprintf("v%d", s.varId)
	argPrep := fmt.Sprintf("	uint64_t %s = %d;\n", argName, 10)
	s.varId += 1
	return argName, argPrep
}

type PtrToCtxRegType struct {
}

func (t PtrToCtxRegType) String() string {
	return "PTR_TO_CTX"
}

func (t PtrToCtxRegType) Generate(s *BpfProgState) (string, string) {
	argName := fmt.Sprintf("ctx")
	return argName, ""
}

type ConstPtrToMapRegType struct {
}

func (t ConstPtrToMapRegType) String() string {
	return "CONST_PTR_TO_MAP"
}

func (t ConstPtrToMapRegType) Generate(s *BpfProgState) (string, string) {
	//n := rand.Intn(len(s.maps))
	//argName := fmt.Sprintf("&%v", s.maps[n])
	newMapName := fmt.Sprintf("map_%v", len(s.maps))
	s.AddMap(newMapName, "int", "test_ent_t", 17)
	argName := fmt.Sprintf("&%v", newMapName)
	return argName, ""
}

type PtrToMapValueRegType struct {
}

func (t PtrToMapValueRegType) String() string {
	return "PTR_TO_MAP_VALUE"
}

func (t PtrToMapValueRegType) Generate(s *BpfProgState) (string, string) {
	argName := fmt.Sprintf("v%d", s.varId)
	argPrep := fmt.Sprintf("	char %s[%d];\n", argName, 10)
	s.varId += 1
	return argName, argPrep
}

type PtrToStackRegType struct {
}

func (t PtrToStackRegType) String() string {
	return "PTR_TO_STACK"
}

func (t PtrToStackRegType) Generate(s *BpfProgState) (string, string) {
	argName := fmt.Sprintf("v%d", s.varId)
	argPrep := fmt.Sprintf("	char %s[%d];\n", argName, 10)
	s.varId += 1
	return argName, argPrep
}

type PtrToPacketMetaRegType struct {
}

func (t PtrToPacketMetaRegType) String() string {
	return "PTR_TO_PACKET_META"
}

func (t PtrToPacketMetaRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToPacketRegType struct {
}

func (t PtrToPacketRegType) String() string {
	return "PTR_TO_PACKET"
}

func (t PtrToPacketRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToPacketEndRegType struct {
}

func (t PtrToPacketEndRegType) String() string {
	return "PTR_TO_PACKET_END"
}

func (t PtrToPacketEndRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToFlowKeysRegType struct {
}

func (t PtrToFlowKeysRegType) String() string {
	return "PTR_TO_FLOW_KEYS"
}

func (t PtrToFlowKeysRegType) Generate(s *BpfProgState) (string, string) {
	return "ctx->flow_keys", ""
}

type PtrToSocketRegType struct {
}

func (t PtrToSocketRegType) String() string {
	return "PTR_TO_SOCKET"
}

func (t PtrToSocketRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToSockCommonRegType struct {
}

func (t PtrToSockCommonRegType) String() string {
	return "PTR_TO_SOCK_COMMON"
}

func (t PtrToSockCommonRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToTcpSockRegType struct {
}

func (t PtrToTcpSockRegType) String() string {
	return "PTR_TO_TCP_SOCK"
}

func (t PtrToTcpSockRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToTpBufferRegType struct {
}

func (t PtrToTpBufferRegType) String() string {
	return "PTR_TO_TP_BUFFER"
}

func (t PtrToTpBufferRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToXdpSockRegType struct {
}

func (t PtrToXdpSockRegType) String() string {
	return "PTR_TO_XDP_SOCK"
}

func (t PtrToXdpSockRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToBtfIdRegType struct {
}

func (t PtrToBtfIdRegType) String() string {
	return "PTR_TO_BTF_ID"
}

func (t PtrToBtfIdRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToMemRegType struct {
}

func (t PtrToMemRegType) String() string {
	return "PTR_TO_MEM"
}

func (t PtrToMemRegType) Generate(s *BpfProgState) (string, string) {
	argName := fmt.Sprintf("v%d", s.varId)
	argPrep := fmt.Sprintf("	char %s[%d];\n", argName, 10)
	s.varId += 1
	return argName, argPrep
}

type PtrToRdOnlyBufRegType struct {
}

func (t PtrToRdOnlyBufRegType) String() string {
	return "PTR_TO_RDONLY_BUF"
}

func (t PtrToRdOnlyBufRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToRdWrBufRegType struct {
}

func (t PtrToRdWrBufRegType) String() string {
	return "PTR_TO_RDWR_BUF"
}

func (t PtrToRdWrBufRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToPercpuBtfIdRegType struct {
}

func (t PtrToPercpuBtfIdRegType) String() string {
	return "PTR_TO_PERCPU_BTF_ID"
}

func (t PtrToPercpuBtfIdRegType) Generate(s *BpfProgState) (string, string) {
	fmt.Fprintf(s.misc, "extern const int bpf_prog_active __ksym;")
	return "&bpf_prog_active", ""
}

type PtrToFuncRegType struct {
}

func (t PtrToFuncRegType) String() string {
	return "PTR_TO_FUNC"
}

func (t PtrToFuncRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

type PtrToMapKeyRegType struct {
}

func (t PtrToMapKeyRegType) String() string {
	return "PTR_TO_MAP_KEY"
}

func (t PtrToMapKeyRegType) Generate(s *BpfProgState) (string, string) {
	return "", ""
}

//	NOT_INIT = 0,		 /* nothing was written into register */
//	SCALAR_VALUE,		 /* reg doesn't contain a valid pointer */
//	PTR_TO_CTX,		 /* reg points to bpf_context */
//	CONST_PTR_TO_MAP,	 /* reg points to struct bpf_map */
//	PTR_TO_MAP_VALUE,	 /* reg points to map element value */
////	PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
//	PTR_TO_STACK,		 /* reg == frame_pointer + offset */
//	PTR_TO_PACKET_META,	 /* skb->data - meta_len */
//	PTR_TO_PACKET,		 /* reg points to skb->data */
//	PTR_TO_PACKET_END,	 /* skb->data + headlen */
//	PTR_TO_FLOW_KEYS,	 /* reg points to bpf_flow_keys */
//	PTR_TO_SOCKET,		 /* reg points to struct bpf_sock */
////	PTR_TO_SOCKET_OR_NULL,	 /* reg points to struct bpf_sock or NULL */
//	PTR_TO_SOCK_COMMON,	 /* reg points to sock_common */
////	PTR_TO_SOCK_COMMON_OR_NULL, /* reg points to sock_common or NULL */
//	PTR_TO_TCP_SOCK,	 /* reg points to struct tcp_sock */
////	PTR_TO_TCP_SOCK_OR_NULL, /* reg points to struct tcp_sock or NULL */
//	PTR_TO_TP_BUFFER,	 /* reg points to a writable raw tp's buffer */
//	PTR_TO_XDP_SOCK,	 /* reg points to struct xdp_sock */
//	/* PTR_TO_BTF_ID points to a kernel struct that does not need
//	 * to be null checked by the BPF program. This does not imply the
//	 * pointer is _not_ null and in practice this can easily be a null
//	 * pointer when reading pointer chains. The assumption is program
//	 * context will handle null pointer dereference typically via fault
//	 * handling. The verifier must keep this in mind and can make no
//	 * assumptions about null or non-null when doing branch analysis.
//	 * Further, when passed into helpers the helpers can not, without
//	 * additional context, assume the value is non-null.
//	 */
//	PTR_TO_BTF_ID,
//	/* PTR_TO_BTF_ID_OR_NULL points to a kernel struct that has not
//	 * been checked for null. Used primarily to inform the verifier
//	 * an explicit null check is required for this struct.
//	 */
////	PTR_TO_BTF_ID_OR_NULL,
//	PTR_TO_MEM,		 /* reg points to valid memory region */
////	PTR_TO_MEM_OR_NULL,	 /* reg points to valid memory region or NULL */
//	PTR_TO_RDONLY_BUF,	 /* reg points to a readonly buffer */
////	PTR_TO_RDONLY_BUF_OR_NULL, /* reg points to a readonly buffer or NULL */
//	PTR_TO_RDWR_BUF,	 /* reg points to a read/write buffer */
////	PTR_TO_RDWR_BUF_OR_NULL, /* reg points to a read/write buffer or NULL */
//	PTR_TO_PERCPU_BTF_ID,	 /* reg points to a percpu kernel variable */
//	PTR_TO_FUNC,		 /* reg points to a bpf program function */
//	PTR_TO_MAP_KEY,		 /* reg points to a map element key */

var retToRegTypeMap = map[string]string {
	"RET_INTEGER":                      "SCALAR_VALUE",
	"RET_VOID":                         "NOT_INIT",
	"RET_PTR_TO_MAP_VALUE":             "PTR_TO_MAP_VALUE",
	"RET_PTR_TO_MAP_VALUE_OR_NULL":     "PTR_TO_MAP_VALUE",
	"RET_PTR_TO_SOCKET_OR_NULL":        "PTR_TO_SOCKET_VALUE",
	"RET_PTR_TO_TCP_SOCK_OR_NULL":      "PTR_TO_TCP_SOCK",
	"RET_PTR_TO_SOCK_COMMON_OR_NULL":   "PTR_TO_SOCK_COMMON",
	"RET_PTR_TO_ALLOC_MEM_OR_NULL":     "PTR_TO_ALLOC_MEM",
	"RET_PTR_TO_BTF_ID_OR_NULL":        "PTR_TO_BTF_ID",
	"RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL": "PTR_TO_BTF_ID",
	"RET_PTR_TO_MEM_OR_BTF_ID":         "PTR_TO_BTF_ID",
	"RET_PTR_TO_BTF_ID":                "PTR_TO_BTF_ID",
}

type BpfCtxAccess struct {
	regTypeMap map[string][][]string
	others     map[string]*BpfCtxAccess
}

func NewBpfCtxAccess() *BpfCtxAccess {
	newCtxAccess := new(BpfCtxAccess)
	newCtxAccess.regTypeMap = make(map[string][][]string)
	newCtxAccess.others = make(map[string]*BpfCtxAccess)
	return newCtxAccess
}

type BpfRuntimeFuzzer struct {
	helperFuncMap        map[string]*BpfHelperFunc
	progTypeMap          map[string]*BpfProgTypeDef
	ctxAccessMap         map[string]*BpfCtxAccess

	helperProtoMap       map[string]map[string]bool
	helperProtoGrepRe    *regexp.Regexp
	helperProtoRe        *regexp.Regexp
	compatibleRegType    map[string][]RegType
}

func NewBpfRuntimeFuzzer() *BpfRuntimeFuzzer {
	brf := new(BpfRuntimeFuzzer)
	brf.helperFuncMap = make(map[string]*BpfHelperFunc)
	brf.progTypeMap = make(map[string]*BpfProgTypeDef)
	brf.ctxAccessMap = make(map[string]*BpfCtxAccess)
	brf.helperProtoMap = make(map[string]map[string]bool)
	brf.helperProtoGrepRe = regexp.MustCompile(`([./0-9a-zA-Z_-]+):([0-9]+):(?:static\s)?const\sstruct\sbpf_func_proto\s([0-9a-zA-Z_]+)\s=\s\{`)
	brf.helperProtoRe = regexp.MustCompile(`\s+.([0-9a-zA-Z_]+)\s+=\s([0-9a-zA-Z_]+),`)

	map_key_value_types := []RegType{PtrToStackRegType{}, PtrToPacketRegType{}, PtrToPacketMetaRegType{}, PtrToMapKeyRegType{}, PtrToMapValueRegType{}}
	scalar_types := []RegType{ScalarValRegType{}}
	const_map_ptr_types := []RegType{ConstPtrToMapRegType{}}
	context_types := []RegType{PtrToCtxRegType{}}
	sock_types := []RegType{PtrToSockCommonRegType{}, PtrToSocketRegType{}, PtrToTcpSockRegType{}, PtrToXdpSockRegType{}}
	btf_id_sock_common_types := []RegType{PtrToSockCommonRegType{}, PtrToSocketRegType{}, PtrToTcpSockRegType{}, PtrToXdpSockRegType{}, PtrToBtfIdRegType{}}
	fullsock_types := []RegType{PtrToSocketRegType{}}
	btf_ptr_types := []RegType{PtrToBtfIdRegType{}}
	spin_lock_types := []RegType{PtrToMapValueRegType{}}
	mem_types := []RegType{PtrToStackRegType{}, PtrToPacketRegType{}, PtrToPacketMetaRegType{}, PtrToMapKeyRegType{}, PtrToMapValueRegType{}, PtrToMemRegType{}, PtrToRdOnlyBufRegType{}, PtrToRdWrBufRegType{}}
	alloc_mem_types := []RegType{PtrToMemRegType{}}
	int_ptr_types := []RegType{PtrToStackRegType{}, PtrToPacketRegType{}, PtrToPacketMetaRegType{}, PtrToMapKeyRegType{}, PtrToMapValueRegType{}}
	percpu_btf_ptr_types := []RegType{PtrToPercpuBtfIdRegType{}}
	func_ptr_types := []RegType{PtrToFuncRegType{}}
	stack_ptr_types := []RegType{PtrToStackRegType{}}
	const_str_ptr_types := []RegType{PtrToMapValueRegType{}}
	timer_types := []RegType{PtrToMapValueRegType{}}
	all_types := []RegType{ScalarValRegType{}, PtrToCtxRegType{}, ConstPtrToMapRegType{}, PtrToMapValueRegType{}, PtrToStackRegType{}, PtrToPacketMetaRegType{}, PtrToPacketRegType{}, PtrToPacketEndRegType{}, PtrToFlowKeysRegType{}, PtrToSocketRegType{}, PtrToSockCommonRegType{}, PtrToTcpSockRegType{}, PtrToTpBufferRegType{}, PtrToXdpSockRegType{}, PtrToBtfIdRegType{}, PtrToMemRegType{}, PtrToRdOnlyBufRegType{}, PtrToRdWrBufRegType{}, PtrToPercpuBtfIdRegType{}, PtrToFuncRegType{}, PtrToMapKeyRegType{}}

	brf.compatibleRegType = make(map[string][]RegType)
	brf.compatibleRegType["ARG_ANYTHING"] = all_types
	//brf.compatibleRegType["ARG_ANYTHING"] = scalar_types
	brf.compatibleRegType["ARG_PTR_TO_MAP_KEY"] = map_key_value_types
	brf.compatibleRegType["ARG_PTR_TO_MAP_VALUE"] = map_key_value_types
	brf.compatibleRegType["ARG_PTR_TO_UNINIT_MAP_VALUE"] = map_key_value_types
	brf.compatibleRegType["ARG_PTR_TO_MAP_VALUE_OR_NULL"] = map_key_value_types
	brf.compatibleRegType["ARG_CONST_SIZE"] = scalar_types
	brf.compatibleRegType["ARG_CONST_SIZE_OR_ZERO"] = scalar_types
	brf.compatibleRegType["ARG_CONST_ALLOC_SIZE_OR_ZERO"] = scalar_types
	brf.compatibleRegType["ARG_CONST_MAP_PTR"] = const_map_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_CTX"] = context_types
	brf.compatibleRegType["ARG_PTR_TO_CTX_OR_NULL"] = context_types
	brf.compatibleRegType["ARG_PTR_TO_SOCK_COMMON"] = sock_types
	brf.compatibleRegType["ARG_PTR_TO_BTF_ID_SOCK_COMMON"] = btf_id_sock_common_types
	brf.compatibleRegType["ARG_PTR_TO_SOCKET"]= fullsock_types
	brf.compatibleRegType["ARG_PTR_TO_SOCKET_OR_NULL"] = fullsock_types
	brf.compatibleRegType["ARG_PTR_TO_BTF_ID"] = btf_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_SPIN_LOCK"] = spin_lock_types
	brf.compatibleRegType["ARG_PTR_TO_MEM"] = mem_types
	brf.compatibleRegType["ARG_PTR_TO_MEM_OR_NULL"] = mem_types
	brf.compatibleRegType["ARG_PTR_TO_UNINIT_MEM"] = mem_types
	brf.compatibleRegType["ARG_PTR_TO_ALLOC_MEM"] = alloc_mem_types
	brf.compatibleRegType["ARG_PTR_TO_ALLOC_MEM_OR_NULL"] = alloc_mem_types
	brf.compatibleRegType["ARG_PTR_TO_INT"] = int_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_LONG"] = int_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_PERCPU_BTF_ID"] = percpu_btf_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_FUNC"] = func_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_STACK_OR_NULL"] = stack_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_CONST_STR"] = const_str_ptr_types
	brf.compatibleRegType["ARG_PTR_TO_TIMER"]= timer_types

	return brf
}

func (brf *BpfRuntimeFuzzer) InitFromSrc(hMap map[string]*BpfHelperFunc, ptMap map[string]*BpfProgTypeDef, caMap map[string]*BpfCtxAccess) {
	brf.helperFuncMap = hMap
	brf.progTypeMap = ptMap
	brf.ctxAccessMap = caMap

	for name, pt := range brf.progTypeMap {
		pt.ctxAccess = brf.ctxAccessMap[name]
	}
}

func (brf *BpfRuntimeFuzzer) genBpfHelperCallArg(s *BpfProgState, call *BpfCall, i int) bool {
	argType := call.helper.Args[i]
	fmt.Printf("gen %v arg[%v] %v ", call.helper.Name, i, argType)

	if nOutOf(1, 3) && brf.genRandBpfHelperCall(s, argType) {
		call.args[i] = s.calls[len(s.calls)-1].ret
		return true
	} else if nOutOf(1, 2) && brf.genRandBpfCtxAccess(s, argType) {
		ranges, _ := s.pt.ctxAccess.regTypeMap[argType]
		n := rand.Intn(len(ranges))
		call.args[i] = ranges[n][2]
		return true
	} else if a, p, ok := brf.genRandDirectAccess(s, argType); ok {
		call.prepare[i] = p
		call.args[i] = a
		return true
	} else {
		return false
	}
}

func (brf *BpfRuntimeFuzzer) genRandDirectAccess(s *BpfProgState, argType string) (string, string, bool) {
	for i := 0; i < 5; i++ {
		n := rand.Intn(len(brf.compatibleRegType[argType]))
		a, p := brf.compatibleRegType[argType][n].Generate(s)
		if a != "" {
			fmt.Printf(" direct %v\n", brf.compatibleRegType[argType][n].String())
			return a, p, true
		}
	}
	return "", "", false
}

func (brf *BpfRuntimeFuzzer) genRandBpfCtxAccess(s *BpfProgState, argType string) bool {
	if _, ok := s.pt.ctxAccess.regTypeMap[argType]; ok {
		fmt.Printf(" ctx access\n")
		return true
	}
	return false
}

func bpfRetType(call *BpfCall) string {
	if call.helper.Ret == "RET_INTEGER" {
		return "uint64_t"
	} else if call.helper.Ret == "RET_PTR_TO_MAP_VALUE" || call.helper.Ret == "RET_PTR_TO_MAP_VALUE_OR_NULL" {
		return "test_ent_t*"
	} else if call.helper.Ret == "RET_PTR_TO_BTF_ID_OR_NULL" {
		return "void*"
	} else if call.helper.Ret == "RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL" || call.helper.Ret == "RET_PTR_TO_MEM_OR_BTF_ID" || call.helper.Ret == "RET_PTR_TO_BTF_ID" {
		return "void*"
	} else {
		return ""
	}
}

var recursive int

func (brf *BpfRuntimeFuzzer) genBpfHelperCall(s *BpfProgState, helper *BpfHelperFunc) bool {
	recursive += 1
	if recursive > 100 {
		return false
	}

	call := NewBpfCall(helper)
	for i := 0; i < len(helper.Args); {
		if brf.genBpfHelperCallArg(s, call, i) {
			i++
		}
	}

	if typ := bpfRetType(call); typ != "" {
		call.retType = typ
		call.ret = fmt.Sprintf("v%v", s.varId)
		s.varId += 1
	}
	s.calls = append(s.calls, call)
	recursive -= 1
	return true
}

func (brf *BpfRuntimeFuzzer) genRandBpfHelperCall(s *BpfProgState, argType string) bool {
	var compatibleHelpers []int
	for i, helper := range s.pt.Helpers {
		for _, regType := range brf.compatibleRegType[argType] {
			if retToRegTypeMap[helper.Ret] == regType.String() {
				compatibleHelpers = append(compatibleHelpers, i)
				break
			}
		}
	}
	if len(compatibleHelpers) == 0 {
		return false
	} else {
		n := compatibleHelpers[rand.Intn(len(compatibleHelpers))]
//	n := rand.Intn(len(s.pt.Helpers))
		fmt.Printf(" helper ret\n")
		return brf.genBpfHelperCall(s, s.pt.Helpers[n])
	}
}

func WriteFile(s *bytes.Buffer, path string) {
	outf, err := os.Create(path)
	if err != nil {
		fmt.Printf("failed to create output file: %v", err)
		return
	}
	defer outf.Close()

	outf.Write(s.Bytes())
}

//func (brf *BpfRuntimeFuzzer) GenBpfInsns() (*BpfProgState, bool) {
func (brf *BpfRuntimeFuzzer) GenBpfInsns() []byte {
	ok := false
	var prog *BpfProgState
	var m *bcc.Module
	for ; m == nil; {
		for ; !ok; {
			prog, ok = brf.GenBpfFuncFuzzer()
		}

		s := brf.WriteFuzzerSource(prog)
		WriteFile(s, "template.log")
		m = bcc.NewModule(s.String(), []string{"-Wint-conversion"})
	}
	insns, err := m.GetInsns("func")
	if err != nil {
		fmt.Printf("err\n")
	} else {
		for i := 0; i < len(insns)/8; i++ {
			fmt.Printf("%d	%x\n", i, insns[i*8: i*8+8])
		}
	}
	return insns
//	return prog, true
}

func (brf *BpfRuntimeFuzzer) GenBpfFuncFuzzer() (*BpfProgState, bool) {
	//rand.Seed(time.Now().UnixNano())
	var ptKeys []string
	for name, _ := range brf.progTypeMap {
		ptKeys = append(ptKeys, name)
	}
	pt := brf.progTypeMap[ptKeys[rand.Intn(len(ptKeys))]]

	s := NewBpfProgState(brf, pt)

	helper := pt.Helpers[rand.Intn(len(pt.Helpers))]
	fmt.Printf("gen %v %v\n", pt.Name, helper.Name)
	return s, brf.genBpfHelperCall(s, helper)
}

func (brf *BpfRuntimeFuzzer) WriteFuzzerSource(prog *BpfProgState) *bytes.Buffer {
	s := new(bytes.Buffer)

	fmt.Fprintf(s, "typedef struct test_ent_t {\n")
	fmt.Fprintf(s, "    uint64_t e1;\n")
	fmt.Fprintf(s, "    uint64_t e2;\n")
	fmt.Fprintf(s, "} test_ent_t;\n\n")

	for _, bpfMap := range prog.maps {
		fmt.Fprintf(s, "BPF_HASH(%s, %s, %s, %d);\n", bpfMap.name, bpfMap.key, bpfMap.ent, bpfMap.size)
	}

	fmt.Fprintf(s, "int func(%s *ctx) {\n", prog.pt.User)
	for _, call := range prog.calls {
		for _, p := range call.prepare {
			fmt.Fprintf(s, "%v", p)
		}
		if call.retType != "" {
			fmt.Fprintf(s, "	%s %s = %s(", call.retType, call.ret, call.helper.Name)
		} else {
			fmt.Fprintf(s, "	%s(", call.helper.Name)
		}
		for i, arg := range call.args {
			fmt.Fprintf(s, "%v", arg)

			if i < len(call.args)-1 {
				fmt.Fprintf(s, ", ")
			}
		}
		fmt.Fprintf(s, ");\n")
	}

	fmt.Fprintf(s, "	return 0;\n")
	fmt.Fprintf(s, "}\n")
	return s
}
