package prog

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

