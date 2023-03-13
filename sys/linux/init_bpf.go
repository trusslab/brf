package linux

import (
	"encoding/binary"
	"fmt"

	"github.com/google/syzkaller/prog"
)

func (arch *arch) generateBtfFuncInfoStruct(g *prog.Gen, typ *prog.StructType, dir prog.Dir, off uint64, id uint64) (arg prog.Arg, calls []*prog.Call) {
	args := make([]prog.Arg, len(typ.Fields))

	args[0] = prog.MakeConstArg(typ.Fields[0].Type, typ.Fields[0].Dir(dir), off)
	args[1] = prog.MakeConstArg(typ.Fields[1].Type, typ.Fields[1].Dir(dir), id)

	group := prog.MakeGroupArg(typ, dir, args)
	return group, calls
}

func (arch *arch) generateBtfFuncInfoArray(g *prog.Gen, typ *prog.ArrayType, dir prog.Dir, data []byte, cnt int) (arg prog.Arg, calls []*prog.Call) {
	count := uint64(cnt)
	var inner []prog.Arg
	for i := uint64(0); i < count; i++ {
		structType := typ.Elem.(*prog.StructType)
		off := binary.LittleEndian.Uint64(data[8*i : 8*i+4])
		id := binary.LittleEndian.Uint64(data[8*i+4 : 8*i+8])
		arg1, calls1 := arch.generateBtfFuncInfoStruct(g, structType, dir, off, id)
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return prog.MakeGroupArg(typ, dir, inner), calls
}

func (arch *arch) generateBtfLineInfoStruct(g *prog.Gen, typ *prog.StructType, dir prog.Dir, io uint64, fno uint64, lo uint64, lc uint64) (arg prog.Arg, calls []*prog.Call) {
	args := make([]prog.Arg, len(typ.Fields))

	args[0] = prog.MakeConstArg(typ.Fields[0].Type, typ.Fields[0].Dir(dir), io)
	args[1] = prog.MakeConstArg(typ.Fields[1].Type, typ.Fields[1].Dir(dir), fno)
	args[2] = prog.MakeConstArg(typ.Fields[2].Type, typ.Fields[2].Dir(dir), lo)
	args[3] = prog.MakeConstArg(typ.Fields[3].Type, typ.Fields[3].Dir(dir), lc)

	group := prog.MakeGroupArg(typ, dir, args)
	return group, calls
}

func (arch *arch) generateBtfLineInfoArray(g *prog.Gen, typ *prog.ArrayType, dir prog.Dir, data []byte, cnt int) (arg prog.Arg, calls []*prog.Call) {
	count := uint64(cnt)
	var inner []prog.Arg
	for i := uint64(0); i < count; i++ {
		structType := typ.Elem.(*prog.StructType)
		io := binary.LittleEndian.Uint64(data[16*i : 16*i+4])
		fno := binary.LittleEndian.Uint64(data[16*i+4 : 16*i+8])
		lo := binary.LittleEndian.Uint64(data[16*i+8 : 16*i+12])
		lc := binary.LittleEndian.Uint64(data[16*i+12 : 16*i+16])
		arg1, calls1 := arch.generateBtfLineInfoStruct(g, structType, dir, io, fno, lo, lc)
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return prog.MakeGroupArg(typ, dir, inner), calls
}

func (arch *arch) generateBpfInsnStruct(g *prog.Gen, typ *prog.StructType, dir prog.Dir, insn uint64) (arg prog.Arg, calls []*prog.Call) {
	args := make([]prog.Arg, len(typ.Fields))

	var offset uint64
	for i, field := range typ.Fields {
		bitfieldLen := field.Type.(*prog.IntType).BitfieldLen
		if bitfieldLen == 0 {
			bitfieldLen = 8 * field.Type.(*prog.IntType).TypeSize
		}
		mask := (uint64(1) << bitfieldLen) - 1
		fmt.Printf("offset[%d]=%d %x\n", i, offset, (insn>>offset)&mask)
		args[i] = prog.MakeConstArg(field.Type, field.Dir(dir), (insn>>offset)&mask)
		offset += bitfieldLen
	}

	group := prog.MakeGroupArg(typ, dir, args)
	return group, calls
}

func (arch *arch) generateBpfInsnArray(g *prog.Gen, typ *prog.ArrayType, dir prog.Dir, insns []byte) (arg prog.Arg, calls []*prog.Call) {
	count := uint64(len(insns) / 8)
	var inner []prog.Arg
	for i := uint64(0); i < count; i++ {
		insnUnion0 := typ.Elem.(*prog.UnionType).Fields[0]
		insnType, insnDir := insnUnion0.Type.(*prog.StructType), insnUnion0.Dir(dir)
		insn := binary.LittleEndian.Uint64(insns[8*i : 8*i+8])
		fmt.Printf("debug insn[%d]=%x\n", i, insn)
		arg1, calls1 := arch.generateBpfInsnStruct(g, insnType, insnDir, insn)
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return prog.MakeGroupArg(typ, dir, inner), calls
}
/*
func (arch *arch) generateBpfProgram(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	fmt.Printf("generateBpfProgram special\n")

	typ := typ0.(*prog.StructType)
	args := make([]prog.Arg, len(typ.Fields))
	callsf := make([][]*prog.Call, len(typ.Fields))

	// Compile program
	ps := prog.Brf.GenBpfProgS(g)
	insns, err := ps.prog.GetInsns("func")
	if err != nil {
		fmt.Printf("err\n")
	} else {
		for i := 0; i < len(insns)/8; i++ {
			fmt.Printf("%d	%x\n", i, insns[i*8:i*8+8])
		}
	}
	btfInfo, err := ps.prog.GetBtfInfo("func")

	// Generate arguments
	field := typ.Fields[0]
	args[0] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(ps.ProgType()))
	field = typ.Fields[1]
	args[1] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(len(insns)/8))

	field = typ.Fields[2]
	// union
	unionType, unionDir := field.Type.(*prog.PtrType).Elem.(*prog.UnionType), field.Type.(*prog.PtrType).ElemDir
	optType, optDir := unionType.Fields[0].Type.(*prog.ArrayType), unionType.Fields[0].Dir(dir)
	opt, calls := arch.generateBpfInsnArray(g, optType, optDir, insns)
	unionArg, unionCalls := prog.MakeUnionArg(unionType, unionDir, opt, 0), calls
	// ptr
	args[2], _ = g.Alloc(field.Type, field.Dir(dir), unionArg)
	calls = append(calls, unionCalls...)

	field = typ.Fields[3]
	licenseBuffer := field.Type.(*prog.PtrType).Elem.(*prog.BufferType)
	licenseData := []byte("GPL\x00")
	inner3 := prog.MakeDataArg(licenseBuffer, dir, licenseData)
	args[3], _ = g.Alloc(field.Type, field.Dir(dir), inner3)
	calls = append(calls, callsf[3]...)
	field = typ.Fields[4]
	args[4] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(2))
	calls = append(calls, callsf[4]...)
	field = typ.Fields[5]
	args[5] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(65536))
	calls = append(calls, callsf[5]...)
	field = typ.Fields[6]
	logBuffer := field.Type.(*prog.PtrType).Elem.(*prog.BufferType)
	data := make([]byte, 65536)
	inner6 := prog.MakeDataArg(logBuffer, dir, data)
	args[6], _ = g.Alloc(field.Type, field.Dir(dir), inner6)
	calls = append(calls, callsf[6]...)
	field = typ.Fields[7]
	args[7] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[7])
	calls = append(calls, callsf[7]...)
	field = typ.Fields[8]
	args[8] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[8])
	calls = append(calls, callsf[8]...)
	field = typ.Fields[9]
	args[9] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[9])
	calls = append(calls, callsf[9]...)
	field = typ.Fields[10]
	args[10] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[10])
	calls = append(calls, callsf[10]...)
	field = typ.Fields[11]
	args[11] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[11])
	calls = append(calls, callsf[11]...)
	field = typ.Fields[12]
	args[12] = prog.MakeResultArg(field.Type, field.Dir(dir), nil, uint64(btfInfo.Prog_btf_fd))
	field = typ.Fields[13]
	args[13] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(btfInfo.Func_info_rec_size))
	field = typ.Fields[14]
	fiType := field.Type.(*prog.PtrType).Elem.(*prog.ArrayType)
	inner14, callsf14 := arch.generateBtfFuncInfoArray(g, fiType, optDir, btfInfo.Func_info, btfInfo.Func_info_cnt)
	args[14], _ = g.Alloc(field.Type, field.Dir(dir), inner14)
	calls = append(calls, callsf14...)
	field = typ.Fields[15]
	args[15] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(btfInfo.Func_info_cnt))
	field = typ.Fields[16]
	args[16] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(btfInfo.Line_info_rec_size))
	field = typ.Fields[17]
	liType := field.Type.(*prog.PtrType).Elem.(*prog.ArrayType)
	inner17, callsf17 := arch.generateBtfLineInfoArray(g, liType, optDir, btfInfo.Line_info, btfInfo.Line_info_cnt)
	args[17], _ = g.Alloc(field.Type, field.Dir(dir), inner17)
	calls = append(calls, callsf17...)
	field = typ.Fields[18]
	args[18] = prog.MakeConstArg(field.Type, field.Dir(dir), uint64(btfInfo.Line_info_cnt))
	field = typ.Fields[19]
	args[19] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[19])
	calls = append(calls, callsf[19]...)
	field = typ.Fields[20]
	args[20] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[20])
	calls = append(calls, callsf[20]...)
	field = typ.Fields[21]
	args[21] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[21])
	calls = append(calls, callsf[21]...)
	field = typ.Fields[22]
	args[22] = g.GenerateArg(field.Type, field.Dir(dir), &callsf[22])
	calls = append(calls, callsf[22]...)

	group := prog.MakeGroupArg(typ, dir, args)
	return group, calls
}
*/
