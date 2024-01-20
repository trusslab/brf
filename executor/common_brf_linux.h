
#define OBJ_LIST_SIZE 32

static struct bpf_object *bpf_object_list[OBJ_LIST_SIZE];

struct bpf_res {
	int prog_fds[32];
	int prog_num;
	int map_fds[32];
	int map_num;
};

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

static struct bpf_object *find_bpf_object_by_basename(const char *path)
{
	char name[BPF_OBJ_NAME_LEN];
	char *end;
	int i = 0;

	for (i = 0; i < OBJ_LIST_SIZE; i++) {
		if (!bpf_object_list[i])
			break;

		strncpy(name, basename(path), sizeof(name) - 1);
		end = strchr(name, '.');
		if (end)
			*end = 0;

		if (strcmp(bpf_object__name(bpf_object_list[i]), name) == 0)
			return bpf_object_list[i];
	}
	return NULL;
}

static long syz_bpf_prog_load(volatile long a0, volatile long a1)
{
	const char *file = (char *)a0;
	struct bpf_res *res = (struct bpf_res *)a1;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int i, err;

	obj = find_bpf_object_by_basename(file);
	if (!obj) {
		debug("syz_bpf_prog_load: cannot find %s", file);
		return -1;
	}

	err = bpf_object__load(obj);
	if (err) {
		debug("syz_bpf_prog_load: failed to load bpf prog, errno %d", err);
		return -1;
	}

	i = 0;
	bpf_object__for_each_program(prog, obj)
		res->prog_fds[i++] = bpf_program__fd(prog);

	i = 0;
	bpf_object__for_each_map(map, obj)
		res->map_fds[i++] = bpf_map__fd(map);

	return res->prog_fds[0];
}
