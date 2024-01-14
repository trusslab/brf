
#define OBJ_LIST_SIZE 32

static struct bpf_object *bpf_object_list[OBJ_LIST_SIZE];

static long syz_bpf_prog_open(volatile long a0)
{
	const char* file = (char*)a0;
	struct bpf_object* obj;
	char bpf_err_buf[256];
	unsigned int i;
	long err;

	obj = bpf_object__open(file);
	err = libbpf_get_error(obj);
	if (err) {
		debug("syz_bpf_prog_open: failed to open bpf object %s: %s", file, bpf_err_buf);
		return -1;
	}

	for (i = 0; i < OBJ_LIST_SIZE; i++) {
		if (!bpf_object_list[i]) {
			bpf_object_list[i] = obj;
			return 0;
		}
	}

	debug("syz_bpf_prog_open: bpf_object_list full");
	return -1;
}

