// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	brfStats          [BrfStatCount][4]uint64 // total loaded verification_fail attach_fail
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}
	corpusPrios  []int64
	sumPrios     int64

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex
}

type FuzzerSnapshot struct {
	corpus      []*prog.Prog
	corpusPrios []int64
	sumPrios    int64
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCollide
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
	StatCollide:   "exec collide",
}

const (
	BPF_PROG_TYPE_SOCKET_FILTER Stat = iota
	BPF_PROG_TYPE_KPROBE
	BPF_PROG_TYPE_SCHED_CLS
	BPF_PROG_TYPE_SCHED_ACT
	BPF_PROG_TYPE_TRACEPOINT
	BPF_PROG_TYPE_XDP
	BPF_PROG_TYPE_PERF_EVENT
	BPF_PROG_TYPE_CGROUP_SKB
	BPF_PROG_TYPE_CGROUP_SOCK
	BPF_PROG_TYPE_LWT_IN
	BPF_PROG_TYPE_LWT_OUT
	BPF_PROG_TYPE_LWT_XMIT
	BPF_PROG_TYPE_SOCK_OPS
	BPF_PROG_TYPE_SK_SKB
	BPF_PROG_TYPE_CGROUP_DEVICE
	BPF_PROG_TYPE_SK_MSG
	BPF_PROG_TYPE_RAW_TRACEPOINT
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	BPF_PROG_TYPE_LWT_SEG6LOCAL
	BPF_PROG_TYPE_LIRC_MODE2
	BPF_PROG_TYPE_SK_REUSEPORT
	BPF_PROG_TYPE_FLOW_DISSECTOR
	BPF_PROG_TYPE_CGROUP_SYSCTL
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
	BPF_PROG_TYPE_CGROUP_SOCKOPT
	BPF_PROG_TYPE_TRACING
	BPF_PROG_TYPE_STRUCT_OPS
	BPF_PROG_TYPE_EXT
	BPF_PROG_TYPE_LSM
	BPF_PROG_TYPE_SK_LOOKUP
	BPF_PROG_TYPE_SYSCALL
	BPF_FUNC_map_lookup_elem
	BPF_FUNC_map_update_elem
	BPF_FUNC_map_delete_elem
	BPF_FUNC_probe_read
	BPF_FUNC_ktime_get_ns
	BPF_FUNC_trace_printk
	BPF_FUNC_get_prandom_u32
	BPF_FUNC_get_smp_processor_id
	BPF_FUNC_skb_store_bytes
	BPF_FUNC_l3_csum_replace
	BPF_FUNC_l4_csum_replace
	BPF_FUNC_tail_call
	BPF_FUNC_clone_redirect
	BPF_FUNC_get_current_pid_tgid
	BPF_FUNC_get_current_uid_gid
	BPF_FUNC_get_current_comm
	BPF_FUNC_get_cgroup_classid
	BPF_FUNC_skb_vlan_push
	BPF_FUNC_skb_vlan_pop
	BPF_FUNC_skb_get_tunnel_key
	BPF_FUNC_skb_set_tunnel_key
	BPF_FUNC_perf_event_read
	BPF_FUNC_redirect
	BPF_FUNC_get_route_realm
	BPF_FUNC_perf_event_output
	BPF_FUNC_skb_load_bytes
	BPF_FUNC_get_stackid
	BPF_FUNC_csum_diff
	BPF_FUNC_skb_get_tunnel_opt
	BPF_FUNC_skb_set_tunnel_opt
	BPF_FUNC_skb_change_proto
	BPF_FUNC_skb_change_type
	BPF_FUNC_skb_under_cgroup
	BPF_FUNC_get_hash_recalc
	BPF_FUNC_get_current_task
	BPF_FUNC_probe_write_user
	BPF_FUNC_current_task_under_cgroup
	BPF_FUNC_skb_change_tail
	BPF_FUNC_skb_pull_data
	BPF_FUNC_csum_update
	BPF_FUNC_set_hash_invalid
	BPF_FUNC_get_numa_node_id
	BPF_FUNC_skb_change_head
	BPF_FUNC_xdp_adjust_head
	BPF_FUNC_probe_read_str
	BPF_FUNC_get_socket_cookie
	BPF_FUNC_get_socket_uid
	BPF_FUNC_set_hash
	BPF_FUNC_setsockopt
	BPF_FUNC_skb_adjust_room
	BPF_FUNC_redirect_map
	BPF_FUNC_sk_redirect_map
	BPF_FUNC_sock_map_update
	BPF_FUNC_xdp_adjust_meta
	BPF_FUNC_perf_event_read_value
	BPF_FUNC_perf_prog_read_value
	BPF_FUNC_getsockopt
	BPF_FUNC_override_return
	BPF_FUNC_sock_ops_cb_flags_set
	BPF_FUNC_msg_redirect_map
	BPF_FUNC_msg_apply_bytes
	BPF_FUNC_msg_cork_bytes
	BPF_FUNC_msg_pull_data
	BPF_FUNC_bind
	BPF_FUNC_xdp_adjust_tail
	BPF_FUNC_skb_get_xfrm_state
	BPF_FUNC_get_stack
	BPF_FUNC_skb_load_bytes_relative
	BPF_FUNC_fib_lookup
	BPF_FUNC_sock_hash_update
	BPF_FUNC_msg_redirect_hash
	BPF_FUNC_sk_redirect_hash
	BPF_FUNC_lwt_push_encap
	BPF_FUNC_lwt_seg6_store_bytes
	BPF_FUNC_lwt_seg6_adjust_srh
	BPF_FUNC_lwt_seg6_action
	BPF_FUNC_rc_repeat
	BPF_FUNC_rc_keydown
	BPF_FUNC_skb_cgroup_id
	BPF_FUNC_get_current_cgroup_id
	BPF_FUNC_get_local_storage
	BPF_FUNC_sk_select_reuseport
	BPF_FUNC_skb_ancestor_cgroup_id
	BPF_FUNC_sk_lookup_tcp
	BPF_FUNC_sk_lookup_udp
	BPF_FUNC_sk_release
	BPF_FUNC_map_push_elem
	BPF_FUNC_map_pop_elem
	BPF_FUNC_map_peek_elem
	BPF_FUNC_msg_push_data
	BPF_FUNC_msg_pop_data
	BPF_FUNC_rc_pointer_rel
	BPF_FUNC_spin_lock
	BPF_FUNC_spin_unlock
	BPF_FUNC_sk_fullsock
	BPF_FUNC_tcp_sock
	BPF_FUNC_skb_ecn_set_ce
	BPF_FUNC_get_listener_sock
	BPF_FUNC_skc_lookup_tcp
	BPF_FUNC_tcp_check_syncookie
	BPF_FUNC_sysctl_get_name
	BPF_FUNC_sysctl_get_current_value
	BPF_FUNC_sysctl_get_new_value
	BPF_FUNC_sysctl_set_new_value
	BPF_FUNC_strtol
	BPF_FUNC_strtoul
	BPF_FUNC_sk_storage_get
	BPF_FUNC_sk_storage_delete
	BPF_FUNC_send_signal
	BPF_FUNC_tcp_gen_syncookie
	BPF_FUNC_skb_output
	BPF_FUNC_probe_read_user
	BPF_FUNC_probe_read_kernel
	BPF_FUNC_probe_read_user_str
	BPF_FUNC_probe_read_kernel_str
	BPF_FUNC_tcp_send_ack
	BPF_FUNC_send_signal_thread
	BPF_FUNC_jiffies64
	BPF_FUNC_read_branch_records
	BPF_FUNC_get_ns_current_pid_tgid
	BPF_FUNC_xdp_output
	BPF_FUNC_get_netns_cookie
	BPF_FUNC_get_current_ancestor_cgroup_id
	BPF_FUNC_sk_assign
	BPF_FUNC_ktime_get_boot_ns
	BPF_FUNC_seq_printf
	BPF_FUNC_seq_write
	BPF_FUNC_sk_cgroup_id
	BPF_FUNC_sk_ancestor_cgroup_id
	BPF_FUNC_ringbuf_output
	BPF_FUNC_ringbuf_reserve
	BPF_FUNC_ringbuf_submit
	BPF_FUNC_ringbuf_discard
	BPF_FUNC_ringbuf_query
	BPF_FUNC_csum_level
	BPF_FUNC_skc_to_tcp6_sock
	BPF_FUNC_skc_to_tcp_sock
	BPF_FUNC_skc_to_tcp_timewait_sock
	BPF_FUNC_skc_to_tcp_request_sock
	BPF_FUNC_skc_to_udp6_sock
	BPF_FUNC_get_task_stack
	BPF_FUNC_load_hdr_opt
	BPF_FUNC_store_hdr_opt
	BPF_FUNC_reserve_hdr_opt
	BPF_FUNC_inode_storage_get
	BPF_FUNC_inode_storage_delete
	BPF_FUNC_d_path
	BPF_FUNC_copy_from_user
	BPF_FUNC_snprintf_btf
	BPF_FUNC_seq_printf_btf
	BPF_FUNC_skb_cgroup_classid
	BPF_FUNC_redirect_neigh
	BPF_FUNC_per_cpu_ptr
	BPF_FUNC_this_cpu_ptr
	BPF_FUNC_redirect_peer
	BPF_FUNC_task_storage_get
	BPF_FUNC_task_storage_delete
	BPF_FUNC_get_current_task_btf
	BPF_FUNC_bprm_opts_set
	BPF_FUNC_ktime_get_coarse_ns
	BPF_FUNC_ima_inode_hash
	BPF_FUNC_sock_from_file
	BPF_FUNC_check_mtu
	BPF_FUNC_for_each_map_elem
	BPF_FUNC_snprintf
	BPF_FUNC_sys_bpf
	BPF_FUNC_btf_find_by_name_kind
	BPF_FUNC_sys_close
	BPF_FUNC_timer_init
	BPF_FUNC_timer_set_callback
	BPF_FUNC_timer_start
	BPF_FUNC_timer_cancel
	BPF_FUNC_get_func_ip
	BPF_FUNC_get_attach_cookie
	BPF_FUNC_task_pt_regs
	BPF_MAP_TYPE_HASH
	BPF_MAP_TYPE_ARRAY
	BPF_MAP_TYPE_PROG_ARRAY
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	BPF_MAP_TYPE_PERCPU_HASH
	BPF_MAP_TYPE_PERCPU_ARRAY
	BPF_MAP_TYPE_STACK_TRACE
	BPF_MAP_TYPE_CGROUP_ARRAY
	BPF_MAP_TYPE_LRU_HASH
	BPF_MAP_TYPE_LRU_PERCPU_HASH
	BPF_MAP_TYPE_LPM_TRIE
	BPF_MAP_TYPE_ARRAY_OF_MAPS
	BPF_MAP_TYPE_HASH_OF_MAPS
	BPF_MAP_TYPE_DEVMAP
	BPF_MAP_TYPE_SOCKMAP
	BPF_MAP_TYPE_CPUMAP
	BPF_MAP_TYPE_XSKMAP
	BPF_MAP_TYPE_SOCKHASH
	BPF_MAP_TYPE_CGROUP_STORAGE
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	BPF_MAP_TYPE_QUEUE
	BPF_MAP_TYPE_STACK
	BPF_MAP_TYPE_SK_STORAGE
	BPF_MAP_TYPE_DEVMAP_HASH
	BPF_MAP_TYPE_STRUCT_OPS
	BPF_MAP_TYPE_RINGBUF
	BPF_MAP_TYPE_INODE_STORAGE
	BPF_MAP_TYPE_TASK_STORAGE
	BPF_BRF_NINSN
	BPF_BRF_NFUNC
	BPF_BRF_NMAP
	BPF_BRF_NRUN
	BrfStatCount
)

var brfStatNames = [BrfStatCount]string{
	BPF_PROG_TYPE_SOCKET_FILTER: "BPF_PROG_TYPE_SOCKET_FILTER",
	BPF_PROG_TYPE_KPROBE: "BPF_PROG_TYPE_KPROBE",
	BPF_PROG_TYPE_SCHED_CLS: "BPF_PROG_TYPE_SCHED_CLS",
	BPF_PROG_TYPE_SCHED_ACT: "BPF_PROG_TYPE_SCHED_ACT",
	BPF_PROG_TYPE_TRACEPOINT: "BPF_PROG_TYPE_TRACEPOINT",
	BPF_PROG_TYPE_XDP: "BPF_PROG_TYPE_XDP",
	BPF_PROG_TYPE_PERF_EVENT: "BPF_PROG_TYPE_PERF_EVENT",
	BPF_PROG_TYPE_CGROUP_SKB: "BPF_PROG_TYPE_CGROUP_SKB",
	BPF_PROG_TYPE_CGROUP_SOCK: "BPF_PROG_TYPE_CGROUP_SOCK",
	BPF_PROG_TYPE_LWT_IN: "BPF_PROG_TYPE_LWT_IN",
	BPF_PROG_TYPE_LWT_OUT: "BPF_PROG_TYPE_LWT_OUT",
	BPF_PROG_TYPE_LWT_XMIT: "BPF_PROG_TYPE_LWT_XMIT",
	BPF_PROG_TYPE_SOCK_OPS: "BPF_PROG_TYPE_SOCK_OPS",
	BPF_PROG_TYPE_SK_SKB: "BPF_PROG_TYPE_SK_SKB",
	BPF_PROG_TYPE_CGROUP_DEVICE: "BPF_PROG_TYPE_CGROUP_DEVICE",
	BPF_PROG_TYPE_SK_MSG: "BPF_PROG_TYPE_SK_MSG",
	BPF_PROG_TYPE_RAW_TRACEPOINT: "BPF_PROG_TYPE_RAW_TRACEPOINT",
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR: "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
	BPF_PROG_TYPE_LWT_SEG6LOCAL: "BPF_PROG_TYPE_LWT_SEG6LOCAL",
	BPF_PROG_TYPE_LIRC_MODE2: "BPF_PROG_TYPE_LIRC_MODE2",
	BPF_PROG_TYPE_SK_REUSEPORT: "BPF_PROG_TYPE_SK_REUSEPORT",
	BPF_PROG_TYPE_FLOW_DISSECTOR: "BPF_PROG_TYPE_FLOW_DISSECTOR",
	BPF_PROG_TYPE_CGROUP_SYSCTL: "BPF_PROG_TYPE_CGROUP_SYSCTL",
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
	BPF_PROG_TYPE_CGROUP_SOCKOPT: "BPF_PROG_TYPE_CGROUP_SOCKOPT",
	BPF_PROG_TYPE_TRACING: "BPF_PROG_TYPE_TRACING",
	BPF_PROG_TYPE_STRUCT_OPS: "BPF_PROG_TYPE_STRUCT_OPS",
	BPF_PROG_TYPE_EXT: "BPF_PROG_TYPE_EXT",
	BPF_PROG_TYPE_LSM: "BPF_PROG_TYPE_LSM",
	BPF_PROG_TYPE_SK_LOOKUP: "BPF_PROG_TYPE_SK_LOOKUP",
	BPF_PROG_TYPE_SYSCALL: "BPF_PROG_TYPE_SYSCALL",
	BPF_FUNC_map_lookup_elem: "BPF_FUNC_map_lookup_elem",
	BPF_FUNC_map_update_elem: "BPF_FUNC_map_update_elem",
	BPF_FUNC_map_delete_elem: "BPF_FUNC_map_delete_elem",
	BPF_FUNC_probe_read: "BPF_FUNC_probe_read",
	BPF_FUNC_ktime_get_ns: "BPF_FUNC_ktime_get_ns",
	BPF_FUNC_trace_printk: "BPF_FUNC_trace_printk",
	BPF_FUNC_get_prandom_u32: "BPF_FUNC_get_prandom_u32",
	BPF_FUNC_get_smp_processor_id: "BPF_FUNC_get_smp_processor_id",
	BPF_FUNC_skb_store_bytes: "BPF_FUNC_skb_store_bytes",
	BPF_FUNC_l3_csum_replace: "BPF_FUNC_l3_csum_replace",
	BPF_FUNC_l4_csum_replace: "BPF_FUNC_l4_csum_replace",
	BPF_FUNC_tail_call: "BPF_FUNC_tail_call",
	BPF_FUNC_clone_redirect: "BPF_FUNC_clone_redirect",
	BPF_FUNC_get_current_pid_tgid: "BPF_FUNC_get_current_pid_tgid",
	BPF_FUNC_get_current_uid_gid: "BPF_FUNC_get_current_uid_gid",
	BPF_FUNC_get_current_comm: "BPF_FUNC_get_current_comm",
	BPF_FUNC_get_cgroup_classid: "BPF_FUNC_get_cgroup_classid",
	BPF_FUNC_skb_vlan_push: "BPF_FUNC_skb_vlan_push",
	BPF_FUNC_skb_vlan_pop: "BPF_FUNC_skb_vlan_pop",
	BPF_FUNC_skb_get_tunnel_key: "BPF_FUNC_skb_get_tunnel_key",
	BPF_FUNC_skb_set_tunnel_key: "BPF_FUNC_skb_set_tunnel_key",
	BPF_FUNC_perf_event_read: "BPF_FUNC_perf_event_read",
	BPF_FUNC_redirect: "BPF_FUNC_redirect",
	BPF_FUNC_get_route_realm: "BPF_FUNC_get_route_realm",
	BPF_FUNC_perf_event_output: "BPF_FUNC_perf_event_output",
	BPF_FUNC_skb_load_bytes: "BPF_FUNC_skb_load_bytes",
	BPF_FUNC_get_stackid: "BPF_FUNC_get_stackid",
	BPF_FUNC_csum_diff: "BPF_FUNC_csum_diff",
	BPF_FUNC_skb_get_tunnel_opt: "BPF_FUNC_skb_get_tunnel_opt",
	BPF_FUNC_skb_set_tunnel_opt: "BPF_FUNC_skb_set_tunnel_opt",
	BPF_FUNC_skb_change_proto: "BPF_FUNC_skb_change_proto",
	BPF_FUNC_skb_change_type: "BPF_FUNC_skb_change_type",
	BPF_FUNC_skb_under_cgroup: "BPF_FUNC_skb_under_cgroup",
	BPF_FUNC_get_hash_recalc: "BPF_FUNC_get_hash_recalc",
	BPF_FUNC_get_current_task: "BPF_FUNC_get_current_task",
	BPF_FUNC_probe_write_user: "BPF_FUNC_probe_write_user",
	BPF_FUNC_current_task_under_cgroup: "BPF_FUNC_current_task_under_cgroup",
	BPF_FUNC_skb_change_tail: "BPF_FUNC_skb_change_tail",
	BPF_FUNC_skb_pull_data: "BPF_FUNC_skb_pull_data",
	BPF_FUNC_csum_update: "BPF_FUNC_csum_update",
	BPF_FUNC_set_hash_invalid: "BPF_FUNC_set_hash_invalid",
	BPF_FUNC_get_numa_node_id: "BPF_FUNC_get_numa_node_id",
	BPF_FUNC_skb_change_head: "BPF_FUNC_skb_change_head",
	BPF_FUNC_xdp_adjust_head: "BPF_FUNC_xdp_adjust_head",
	BPF_FUNC_probe_read_str: "BPF_FUNC_probe_read_str",
	BPF_FUNC_get_socket_cookie: "BPF_FUNC_get_socket_cookie",
	BPF_FUNC_get_socket_uid: "BPF_FUNC_get_socket_uid",
	BPF_FUNC_set_hash: "BPF_FUNC_set_hash",
	BPF_FUNC_setsockopt: "BPF_FUNC_setsockopt",
	BPF_FUNC_skb_adjust_room: "BPF_FUNC_skb_adjust_room",
	BPF_FUNC_redirect_map: "BPF_FUNC_redirect_map",
	BPF_FUNC_sk_redirect_map: "BPF_FUNC_sk_redirect_map",
	BPF_FUNC_sock_map_update: "BPF_FUNC_sock_map_update",
	BPF_FUNC_xdp_adjust_meta: "BPF_FUNC_xdp_adjust_meta",
	BPF_FUNC_perf_event_read_value: "BPF_FUNC_perf_event_read_value",
	BPF_FUNC_perf_prog_read_value: "BPF_FUNC_perf_prog_read_value",
	BPF_FUNC_getsockopt: "BPF_FUNC_getsockopt",
	BPF_FUNC_override_return: "BPF_FUNC_override_return",
	BPF_FUNC_sock_ops_cb_flags_set: "BPF_FUNC_sock_ops_cb_flags_set",
	BPF_FUNC_msg_redirect_map: "BPF_FUNC_msg_redirect_map",
	BPF_FUNC_msg_apply_bytes: "BPF_FUNC_msg_apply_bytes",
	BPF_FUNC_msg_cork_bytes: "BPF_FUNC_msg_cork_bytes",
	BPF_FUNC_msg_pull_data: "BPF_FUNC_msg_pull_data",
	BPF_FUNC_bind: "BPF_FUNC_bind",
	BPF_FUNC_xdp_adjust_tail: "BPF_FUNC_xdp_adjust_tail",
	BPF_FUNC_skb_get_xfrm_state: "BPF_FUNC_skb_get_xfrm_state",
	BPF_FUNC_get_stack: "BPF_FUNC_get_stack",
	BPF_FUNC_skb_load_bytes_relative: "BPF_FUNC_skb_load_bytes_relative",
	BPF_FUNC_fib_lookup: "BPF_FUNC_fib_lookup",
	BPF_FUNC_sock_hash_update: "BPF_FUNC_sock_hash_update",
	BPF_FUNC_msg_redirect_hash: "BPF_FUNC_msg_redirect_hash",
	BPF_FUNC_sk_redirect_hash: "BPF_FUNC_sk_redirect_hash",
	BPF_FUNC_lwt_push_encap: "BPF_FUNC_lwt_push_encap",
	BPF_FUNC_lwt_seg6_store_bytes: "BPF_FUNC_lwt_seg6_store_bytes",
	BPF_FUNC_lwt_seg6_adjust_srh: "BPF_FUNC_lwt_seg6_adjust_srh",
	BPF_FUNC_lwt_seg6_action: "BPF_FUNC_lwt_seg6_action",
	BPF_FUNC_rc_repeat: "BPF_FUNC_rc_repeat",
	BPF_FUNC_rc_keydown: "BPF_FUNC_rc_keydown",
	BPF_FUNC_skb_cgroup_id: "BPF_FUNC_skb_cgroup_id",
	BPF_FUNC_get_current_cgroup_id: "BPF_FUNC_get_current_cgroup_id",
	BPF_FUNC_get_local_storage: "BPF_FUNC_get_local_storage",
	BPF_FUNC_sk_select_reuseport: "BPF_FUNC_sk_select_reuseport",
	BPF_FUNC_skb_ancestor_cgroup_id: "BPF_FUNC_skb_ancestor_cgroup_id",
	BPF_FUNC_sk_lookup_tcp: "BPF_FUNC_sk_lookup_tcp",
	BPF_FUNC_sk_lookup_udp: "BPF_FUNC_sk_lookup_udp",
	BPF_FUNC_sk_release: "BPF_FUNC_sk_release",
	BPF_FUNC_map_push_elem: "BPF_FUNC_map_push_elem",
	BPF_FUNC_map_pop_elem: "BPF_FUNC_map_pop_elem",
	BPF_FUNC_map_peek_elem: "BPF_FUNC_map_peek_elem",
	BPF_FUNC_msg_push_data: "BPF_FUNC_msg_push_data",
	BPF_FUNC_msg_pop_data: "BPF_FUNC_msg_pop_data",
	BPF_FUNC_rc_pointer_rel: "BPF_FUNC_rc_pointer_rel",
	BPF_FUNC_spin_lock: "BPF_FUNC_spin_lock",
	BPF_FUNC_spin_unlock: "BPF_FUNC_spin_unlock",
	BPF_FUNC_sk_fullsock: "BPF_FUNC_sk_fullsock",
	BPF_FUNC_tcp_sock: "BPF_FUNC_tcp_sock",
	BPF_FUNC_skb_ecn_set_ce: "BPF_FUNC_skb_ecn_set_ce",
	BPF_FUNC_get_listener_sock: "BPF_FUNC_get_listener_sock",
	BPF_FUNC_skc_lookup_tcp: "BPF_FUNC_skc_lookup_tcp",
	BPF_FUNC_tcp_check_syncookie: "BPF_FUNC_tcp_check_syncookie",
	BPF_FUNC_sysctl_get_name: "BPF_FUNC_sysctl_get_name",
	BPF_FUNC_sysctl_get_current_value: "BPF_FUNC_sysctl_get_current_value",
	BPF_FUNC_sysctl_get_new_value: "BPF_FUNC_sysctl_get_new_value",
	BPF_FUNC_sysctl_set_new_value: "BPF_FUNC_sysctl_set_new_value",
	BPF_FUNC_strtol: "BPF_FUNC_strtol",
	BPF_FUNC_strtoul: "BPF_FUNC_strtoul",
	BPF_FUNC_sk_storage_get: "BPF_FUNC_sk_storage_get",
	BPF_FUNC_sk_storage_delete: "BPF_FUNC_sk_storage_delete",
	BPF_FUNC_send_signal: "BPF_FUNC_send_signal",
	BPF_FUNC_tcp_gen_syncookie: "BPF_FUNC_tcp_gen_syncookie",
	BPF_FUNC_skb_output: "BPF_FUNC_skb_output",
	BPF_FUNC_probe_read_user: "BPF_FUNC_probe_read_user",
	BPF_FUNC_probe_read_kernel: "BPF_FUNC_probe_read_kernel",
	BPF_FUNC_probe_read_user_str: "BPF_FUNC_probe_read_user_str",
	BPF_FUNC_probe_read_kernel_str: "BPF_FUNC_probe_read_kernel_str",
	BPF_FUNC_tcp_send_ack: "BPF_FUNC_tcp_send_ack",
	BPF_FUNC_send_signal_thread: "BPF_FUNC_send_signal_thread",
	BPF_FUNC_jiffies64: "BPF_FUNC_jiffies64",
	BPF_FUNC_read_branch_records: "BPF_FUNC_read_branch_records",
	BPF_FUNC_get_ns_current_pid_tgid: "BPF_FUNC_get_ns_current_pid_tgid",
	BPF_FUNC_xdp_output: "BPF_FUNC_xdp_output",
	BPF_FUNC_get_netns_cookie: "BPF_FUNC_get_netns_cookie",
	BPF_FUNC_get_current_ancestor_cgroup_id	: "BPF_FUNC_get_current_ancestor_cgroup_id",
	BPF_FUNC_sk_assign: "BPF_FUNC_sk_assign",
	BPF_FUNC_ktime_get_boot_ns: "BPF_FUNC_ktime_get_boot_ns",
	BPF_FUNC_seq_printf: "BPF_FUNC_seq_printf",
	BPF_FUNC_seq_write: "BPF_FUNC_seq_write",
	BPF_FUNC_sk_cgroup_id: "BPF_FUNC_sk_cgroup_id",
	BPF_FUNC_sk_ancestor_cgroup_id: "BPF_FUNC_sk_ancestor_cgroup_id",
	BPF_FUNC_ringbuf_output: "BPF_FUNC_ringbuf_output",
	BPF_FUNC_ringbuf_reserve: "BPF_FUNC_ringbuf_reserve",
	BPF_FUNC_ringbuf_submit: "BPF_FUNC_ringbuf_submit",
	BPF_FUNC_ringbuf_discard: "BPF_FUNC_ringbuf_discard",
	BPF_FUNC_ringbuf_query: "BPF_FUNC_ringbuf_query",
	BPF_FUNC_csum_level: "BPF_FUNC_csum_level",
	BPF_FUNC_skc_to_tcp6_sock: "BPF_FUNC_skc_to_tcp6_sock",
	BPF_FUNC_skc_to_tcp_sock: "BPF_FUNC_skc_to_tcp_sock",
	BPF_FUNC_skc_to_tcp_timewait_sock: "BPF_FUNC_skc_to_tcp_timewait_sock",
	BPF_FUNC_skc_to_tcp_request_sock: "BPF_FUNC_skc_to_tcp_request_sock",
	BPF_FUNC_skc_to_udp6_sock: "BPF_FUNC_skc_to_udp6_sock",
	BPF_FUNC_get_task_stack: "BPF_FUNC_get_task_stack",
	BPF_FUNC_load_hdr_opt: "BPF_FUNC_load_hdr_opt",
	BPF_FUNC_store_hdr_opt: "BPF_FUNC_store_hdr_opt",
	BPF_FUNC_reserve_hdr_opt: "BPF_FUNC_reserve_hdr_opt",
	BPF_FUNC_inode_storage_get: "BPF_FUNC_inode_storage_get",
	BPF_FUNC_inode_storage_delete: "BPF_FUNC_inode_storage_delete",
	BPF_FUNC_d_path: "BPF_FUNC_d_path",
	BPF_FUNC_copy_from_user: "BPF_FUNC_copy_from_user",
	BPF_FUNC_snprintf_btf: "BPF_FUNC_snprintf_btf",
	BPF_FUNC_seq_printf_btf: "BPF_FUNC_seq_printf_btf",
	BPF_FUNC_skb_cgroup_classid: "BPF_FUNC_skb_cgroup_classid",
	BPF_FUNC_redirect_neigh: "BPF_FUNC_redirect_neigh",
	BPF_FUNC_per_cpu_ptr: "BPF_FUNC_per_cpu_ptr",
	BPF_FUNC_this_cpu_ptr: "BPF_FUNC_this_cpu_ptr",
	BPF_FUNC_redirect_peer: "BPF_FUNC_redirect_peer",
	BPF_FUNC_task_storage_get: "BPF_FUNC_task_storage_get",
	BPF_FUNC_task_storage_delete: "BPF_FUNC_task_storage_delete",
	BPF_FUNC_get_current_task_btf: "BPF_FUNC_get_current_task_btf",
	BPF_FUNC_bprm_opts_set: "BPF_FUNC_bprm_opts_set",
	BPF_FUNC_ktime_get_coarse_ns: "BPF_FUNC_ktime_get_coarse_ns",
	BPF_FUNC_ima_inode_hash: "BPF_FUNC_ima_inode_hash",
	BPF_FUNC_sock_from_file: "BPF_FUNC_sock_from_file",
	BPF_FUNC_check_mtu: "BPF_FUNC_check_mtu",
	BPF_FUNC_for_each_map_elem: "BPF_FUNC_for_each_map_elem",
	BPF_FUNC_snprintf: "BPF_FUNC_snprintf",
	BPF_FUNC_sys_bpf: "BPF_FUNC_sys_bpf",
	BPF_FUNC_btf_find_by_name_kind: "BPF_FUNC_btf_find_by_name_kind",
	BPF_FUNC_sys_close: "BPF_FUNC_sys_close",
	BPF_FUNC_timer_init: "BPF_FUNC_timer_init",
	BPF_FUNC_timer_set_callback: "BPF_FUNC_timer_set_callback",
	BPF_FUNC_timer_start: "BPF_FUNC_timer_start",
	BPF_FUNC_timer_cancel: "BPF_FUNC_timer_cancel",
	BPF_FUNC_get_func_ip: "BPF_FUNC_get_func_ip",
	BPF_FUNC_get_attach_cookie: "BPF_FUNC_get_attach_cookie",
	BPF_FUNC_task_pt_regs: "BPF_FUNC_task_pt_regs",
	BPF_MAP_TYPE_HASH: "BPF_MAP_TYPE_HASH",
	BPF_MAP_TYPE_ARRAY: "BPF_MAP_TYPE_ARRAY",
	BPF_MAP_TYPE_PROG_ARRAY: "BPF_MAP_TYPE_PROG_ARRAY",
	BPF_MAP_TYPE_PERF_EVENT_ARRAY: "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
	BPF_MAP_TYPE_PERCPU_HASH: "BPF_MAP_TYPE_PERCPU_HASH",
	BPF_MAP_TYPE_PERCPU_ARRAY: "BPF_MAP_TYPE_PERCPU_ARRAY",
	BPF_MAP_TYPE_STACK_TRACE: "BPF_MAP_TYPE_STACK_TRACE",
	BPF_MAP_TYPE_CGROUP_ARRAY: "BPF_MAP_TYPE_CGROUP_ARRAY",
	BPF_MAP_TYPE_LRU_HASH: "BPF_MAP_TYPE_LRU_HASH",
	BPF_MAP_TYPE_LRU_PERCPU_HASH: "BPF_MAP_TYPE_LRU_PERCPU_HASH",
	BPF_MAP_TYPE_LPM_TRIE: "BPF_MAP_TYPE_LPM_TRIE",
	BPF_MAP_TYPE_ARRAY_OF_MAPS: "BPF_MAP_TYPE_ARRAY_OF_MAPS",
	BPF_MAP_TYPE_HASH_OF_MAPS: "BPF_MAP_TYPE_HASH_OF_MAPS",
	BPF_MAP_TYPE_DEVMAP: "BPF_MAP_TYPE_DEVMAP",
	BPF_MAP_TYPE_SOCKMAP: "BPF_MAP_TYPE_SOCKMAP",
	BPF_MAP_TYPE_CPUMAP: "BPF_MAP_TYPE_CPUMAP",
	BPF_MAP_TYPE_XSKMAP: "BPF_MAP_TYPE_XSKMAP",
	BPF_MAP_TYPE_SOCKHASH: "BPF_MAP_TYPE_SOCKHASH",
	BPF_MAP_TYPE_CGROUP_STORAGE: "BPF_MAP_TYPE_CGROUP_STORAGE",
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
	BPF_MAP_TYPE_QUEUE: "BPF_MAP_TYPE_QUEUE",
	BPF_MAP_TYPE_STACK: "BPF_MAP_TYPE_STACK",
	BPF_MAP_TYPE_SK_STORAGE: "BPF_MAP_TYPE_SK_STORAGE",
	BPF_MAP_TYPE_DEVMAP_HASH: "BPF_MAP_TYPE_DEVMAP_HASH",
	BPF_MAP_TYPE_STRUCT_OPS: "BPF_MAP_TYPE_STRUCT_OPS",
	BPF_MAP_TYPE_RINGBUF: "BPF_MAP_TYPE_RINGBUF",
	BPF_MAP_TYPE_INODE_STORAGE: "BPF_MAP_TYPE_INODE_STORAGE",
	BPF_MAP_TYPE_TASK_STORAGE: "BPF_MAP_TYPE_TASK_STORAGE",
	BPF_BRF_NINSN: "BPF_BRF_NINSN",
	BPF_BRF_NFUNC: "BPF_BRF_NFUNC",
	BPF_BRF_NMAP: "BPF_BRF_NMAP",
	BPF_BRF_NRUN: "BPF_BRF_NRUN",
}

func stringToBrfStat(s string) Stat {
	for i, n := range brfStatNames {
		if n == s {
			return Stat(i)
		}
	}
	return Stat(BrfStatCount)
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

// nolint: funlen
func main() {
	debug.SetGCPercent(50)

	var (
		flagName    = flag.String("name", "test", "unique name for manager")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest    = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.Fatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		checkResult:              r.CheckResult,
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)
	fuzzer.mountBpfProgDir()

	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzer.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))
	}
	enableBrf := false
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
		//if len(target.Syscalls[id].Name) >= 8 && target.Syscalls[id].Name[:8] == "syz_bpf_" {
		if target.Syscalls[id].Name == "syz_bpf_prog_open" {
			enableBrf = true
		}
	}
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)

	//fuzzer.disableBpfJIT()
	prog.InitBrf(enableBrf)

	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.Fatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.Fatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := fuzzer.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) mountBpfProgDir() {
	dir := fmt.Sprintf("/mnt/bpf_prog")
	args := []string{dir}
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", "mkdir", args...)
	if err != nil {
		log.Fatalf("failed to create shared dir: %v", err)
	}
	log.Logf(0, "%s", output)

	args = []string{"-t", "9p", "-o", "trans=virtio,version=9p2000.L", "host0", dir}
	output, err = osutil.RunCmd(timeout, "", "mount", args...)
	if err != nil {
		log.Fatalf("failed to mount shared dir: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) disableBpfJIT() {
	args := []string{""}
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", "./mnt/bpf_prog/disable_bpf_jit", args...)
	if err != nil {
		log.Fatalf("failed to disable BPF JIT: %v", err)
	}
	log.Logf(0, "%s", output)

	args = []string{"/proc/sys/net/core/bpf_jit_enable"}
	output, err = osutil.RunCmd(timeout, "", "cat", args...)
	if err != nil {
		log.Fatalf("failed to disable BPF JIT: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * fuzzer.timeouts.Scale).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*fuzzer.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second*fuzzer.timeouts.Scale {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			for stat := Stat(0); stat < BrfStatCount; stat++ {
				v0 := atomic.SwapUint64(&fuzzer.brfStats[stat][0], 0)
				stats[brfStatNames[stat] + "_0"] = v0
				v1 := atomic.SwapUint64(&fuzzer.brfStats[stat][1], 0)
				stats[brfStatNames[stat] + "_1"] = v1
				v2 := atomic.SwapUint64(&fuzzer.brfStats[stat][2], 0)
				stats[brfStatNames[stat] + "_2"] = v2
				v3 := atomic.SwapUint64(&fuzzer.brfStats[stat][3], 0)
				stats[brfStatNames[stat] + "_3"] = v3
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		Stats:          stats,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.Input) {
	a := &rpctype.NewInputArgs{
		Name:  fuzzer.name,
		Input: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.Input) {
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.Candidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if fuzzer.choiceTable != nil {
		fuzzer.checkDisabledCalls(p)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (fuzzer *Fuzzer) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(fuzzer.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range fuzzer.checkResult.EnabledCalls[sandbox] {
				meta := fuzzer.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range fuzzer.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, fuzzer.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) *prog.Prog {
	randVal := r.Int63n(fuzzer.sumPrios + 1)
	idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
		return fuzzer.corpusPrios[i] >= randVal
	})
	return fuzzer.corpus[idx]
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		fuzzer.sumPrios += prio
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{fuzzer.corpus, fuzzer.corpusPrios, fuzzer.sumPrios}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if fuzzer.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
