
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

#define LO_IFINDEX 1

static bool check_attach_res(struct bpf_program *prog, int *res)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.sample_freq = 50,
		.inherit = 1,
		.freq = 1,
	};

	if (*res > 0)
		return true;

	switch (bpf_program__type(prog)) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		*res = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		goto check_fd;
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
		*res = LO_IFINDEX;
		return true;
	case BPF_PROG_TYPE_PERF_EVENT:
		*res = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
		goto check_fd;
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		*res = open("/sys/fs/cgroup", O_RDONLY);
		goto check_fd;
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
		*res = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, "brf",
				      sizeof(int), sizeof(int), 1, &opts);
		goto check_fd;
	case BPF_PROG_TYPE_LIRC_MODE2:
		*res = open("/dev/lirc0", O_RDWR);
		goto check_fd;
	case BPF_PROG_TYPE_SK_REUSEPORT:
		*res = socket(AF_INET, SOCK_DGRAM, 0);
		goto check_fd;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_SK_LOOKUP:
		*res = open("/proc/self/ns/net", O_RDONLY);
		goto check_fd;
	default:
		return true;
	}

check_fd:
	return *res >= 0;
}

static int bpf_program_attach(struct bpf_program *prog, int res, struct bpf_link **link)
{
	struct bpf_tcx_opts tcx_opts;
	struct bpf_netfilter_opts nf_opts;
	int optval = 1;
	int fd, ret;

	if (!check_attach_res(prog, &res)) {
		debug("syz_bpf_prog_attach: no attach point for %s",
		      libbpf_bpf_prog_type_str(bpf_program__type(prog)));
		return -1;
	}

	fd = bpf_program__fd(prog);

	switch (bpf_program__type(prog)) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		return setsockopt(res, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd));
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
	case BPF_PROG_TYPE_TRACING:
		*link = bpf_program__attach(prog);
		goto check_link;
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		*link = bpf_program__attach_tcx(prog, res, &tcx_opts);
		goto check_link;
	case BPF_PROG_TYPE_XDP:
		*link = bpf_program__attach_xdp(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_PERF_EVENT:
		*link = bpf_program__attach_perf_event(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		*link = bpf_program__attach_cgroup(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_LWT_SEG6LOCAL:
		break;
	case BPF_PROG_TYPE_SOCK_OPS:
		*link = bpf_program__attach_cgroup(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_SK_SKB:
		return bpf_prog_attach(fd, res, BPF_SK_SKB_VERDICT, 0);
	case BPF_PROG_TYPE_SK_MSG:
		return bpf_prog_attach(fd, res, BPF_SK_MSG_VERDICT, 0);
	case BPF_PROG_TYPE_LIRC_MODE2:
		return bpf_prog_attach(fd, res, BPF_LIRC_MODE2, 0);
	case BPF_PROG_TYPE_SK_REUSEPORT:
		ret = setsockopt(res, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
		return ret?: setsockopt(res, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &fd, sizeof(fd));
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		*link = bpf_program__attach_netns(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_STRUCT_OPS:
	case BPF_PROG_TYPE_EXT:
	case BPF_PROG_TYPE_LSM:
		*link = bpf_program__attach_lsm(prog);
		goto check_link;
	case BPF_PROG_TYPE_SK_LOOKUP:
		*link = bpf_program__attach_netns(prog, res);
		goto check_link;
	case BPF_PROG_TYPE_SYSCALL:
		break;
	case BPF_PROG_TYPE_NETFILTER:
		*link = bpf_program__attach_netfilter(prog, &nf_opts);
		goto check_link;
	default:
		break;
	}

	return -1;

check_link:
	return (*link != NULL) ? 0 : -1;
}

static long syz_bpf_prog_attach(volatile long a0)
{
	const char *file = (char *)a0;
	int attach_res = -1;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_link *link = NULL;

	obj = find_bpf_object_by_basename(file);
	if (!obj) {
		debug("syz_bpf_prog_attach: cannot find %s", file);
		return -1;
	}

	bpf_object__for_each_program(prog, obj) {
		bpf_program_attach(prog, attach_res, &link);
	}

	return link? bpf_link__fd(link) : 0;
}
