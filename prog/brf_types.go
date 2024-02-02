package prog

const (
	BPF_PROG_TYPE_UNSPEC BpfProgTypeEnum = iota
	BPF_PROG_TYPE_SOCKET_FILTER
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
	BPF_PROG_TYPE_NETFILTER
	BPF_PROG_TYPE_MAX
)

const (
	BPF_FUNC_unspec BpfHelperEnum = iota
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
	BPF_FUNC_get_branch_snapshot
	BPF_FUNC_trace_vprintk
	BPF_FUNC_skc_to_unix_sock
	BPF_FUNC_kallsyms_lookup_name
	BPF_FUNC_find_vma
	BPF_FUNC_loop
	BPF_FUNC_strncmp
	BPF_FUNC_get_func_arg
	BPF_FUNC_get_func_ret
	BPF_FUNC_get_func_arg_cnt
	BPF_FUNC_get_retval
	BPF_FUNC_set_retval
	BPF_FUNC_xdp_get_buff_len
	BPF_FUNC_xdp_load_bytes
	BPF_FUNC_xdp_store_bytes
	BPF_FUNC_copy_from_user_task
	BPF_FUNC_skb_set_tstamp
	BPF_FUNC_ima_file_hash
	BPF_FUNC_kptr_xchg
	BPF_FUNC_map_lookup_percpu_elem
	BPF_FUNC_skc_to_mptcp_sock
	BPF_FUNC_dynptr_from_mem
	BPF_FUNC_ringbuf_reserve_dynptr
	BPF_FUNC_ringbuf_submit_dynptr
	BPF_FUNC_ringbuf_discard_dynptr
	BPF_FUNC_dynptr_read
	BPF_FUNC_dynptr_write
	BPF_FUNC_dynptr_data
	BPF_FUNC_tcp_raw_gen_syncookie_ipv4
	BPF_FUNC_tcp_raw_gen_syncookie_ipv6
	BPF_FUNC_tcp_raw_check_syncookie_ipv4
	BPF_FUNC_tcp_raw_check_syncookie_ipv6
	BPF_FUNC_ktime_get_tai_ns
	BPF_FUNC_user_ringbuf_drain
	BPF_FUNC_cgrp_storage_get
	BPF_FUNC_cgrp_storage_delete
)

var HelperFuncMap = map[string]*BpfHelper{
	"bpf_map_lookup_elem_proto":                &BpfHelper{Uname: "bpf_map_lookup_elem", Enum: BPF_FUNC_map_lookup_elem, Impl: "bpf_map_lookup_elem", Proto: "bpf_map_lookup_elem_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY"}, Ret: "RET_PTR_TO_MAP_VALUE_OR_NULL", PktAccess: true},
	"bpf_map_update_elem_proto":                &BpfHelper{Uname: "bpf_map_update_elem", Enum: BPF_FUNC_map_update_elem, Impl: "bpf_map_update_elem", Proto: "bpf_map_update_elem_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY", "ARG_PTR_TO_MAP_VALUE", "ARG_ANYTHING"}, Ret: "RET_INTEGER", PktAccess: true},
	"bpf_map_delete_elem_proto":                &BpfHelper{Uname: "bpf_map_delete_elem", Enum: BPF_FUNC_map_delete_elem, Impl: "bpf_map_delete_elem", Proto: "bpf_map_delete_elem_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY"}, Ret: "RET_INTEGER", PktAccess: true},
	"bpf_probe_read_compat_proto":              &BpfHelper{Uname: "bpf_probe_read", Enum: BPF_FUNC_probe_read, Impl: "bpf_probe_read_compat", Proto: "bpf_probe_read_compat_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_ktime_get_ns_proto":                   &BpfHelper{Uname: "bpf_ktime_get_ns", Enum: BPF_FUNC_ktime_get_ns, Impl: "bpf_ktime_get_ns", Proto: "bpf_ktime_get_ns_proto", Ret: "RET_INTEGER"},
	"bpf_trace_printk_proto":                   &BpfHelper{Uname: "bpf_trace_printk", Enum: BPF_FUNC_trace_printk, Impl: "bpf_trace_printk", Proto: "bpf_trace_printk_proto", Args: []string{"ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_prandom_u32_proto":                &BpfHelper{Uname: "bpf_get_prandom_u32", Enum: BPF_FUNC_get_prandom_u32, Impl: "bpf_get_prandom_u32", Proto: "bpf_get_prandom_u32_proto", Ret: "RET_INTEGER"},
	"bpf_get_smp_processor_id_proto":           &BpfHelper{Uname: "bpf_get_smp_processor_id", Enum: BPF_FUNC_get_smp_processor_id, Impl: "bpf_get_smp_processor_id", Proto: "bpf_get_smp_processor_id_proto", Ret: "RET_INTEGER"},
	"bpf_get_raw_smp_processor_id_proto":       &BpfHelper{Uname: "bpf_get_smp_processor_id", Enum: BPF_FUNC_get_smp_processor_id, Impl: "bpf_get_raw_cpu_id", Proto: "bpf_get_raw_smp_processor_id_proto", Ret: "RET_INTEGER"},
	"bpf_skb_store_bytes_proto":                &BpfHelper{Uname: "bpf_skb_store_bytes", Enum: BPF_FUNC_skb_store_bytes, Impl: "bpf_skb_store_bytes", Proto: "bpf_skb_store_bytes_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_l3_csum_replace_proto":                &BpfHelper{Uname: "bpf_l3_csum_replace", Enum: BPF_FUNC_l3_csum_replace, Impl: "bpf_l3_csum_replace", Proto: "bpf_l3_csum_replace_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_l4_csum_replace_proto":                &BpfHelper{Uname: "bpf_l4_csum_replace", Enum: BPF_FUNC_l4_csum_replace, Impl: "bpf_l4_csum_replace", Proto: "bpf_l4_csum_replace_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_tail_call_proto":                      &BpfHelper{Uname: "bpf_tail_call", Enum: BPF_FUNC_tail_call, Impl: "NULL", Proto: "bpf_tail_call_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_VOID"},
	"bpf_clone_redirect_proto":                 &BpfHelper{Uname: "bpf_clone_redirect", Enum: BPF_FUNC_clone_redirect, Impl: "bpf_clone_redirect", Proto: "bpf_clone_redirect_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_get_current_pid_tgid_proto":           &BpfHelper{Uname: "bpf_get_current_pid_tgid", Enum: BPF_FUNC_get_current_pid_tgid, Impl: "bpf_get_current_pid_tgid", Proto: "bpf_get_current_pid_tgid_proto", Ret: "RET_INTEGER"},
	"bpf_get_current_uid_gid_proto":            &BpfHelper{Uname: "bpf_get_current_uid_gid", Enum: BPF_FUNC_get_current_uid_gid, Impl: "bpf_get_current_uid_gid", Proto: "bpf_get_current_uid_gid_proto", Ret: "RET_INTEGER"},
	"bpf_get_current_comm_proto":               &BpfHelper{Uname: "bpf_get_current_comm", Enum: BPF_FUNC_get_current_comm, Impl: "bpf_get_current_comm", Proto: "bpf_get_current_comm_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_get_cgroup_classid_proto":             &BpfHelper{Uname: "bpf_get_cgroup_classid", Enum: BPF_FUNC_get_cgroup_classid, Impl: "bpf_get_cgroup_classid", Proto: "bpf_get_cgroup_classid_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_cgroup_classid_curr_proto":        &BpfHelper{Uname: "bpf_get_cgroup_classid", Enum: BPF_FUNC_get_cgroup_classid, Impl: "bpf_get_cgroup_classid_curr", Proto: "bpf_get_cgroup_classid_curr_proto", Ret: "RET_INTEGER"},
	"bpf_skb_vlan_push_proto":                  &BpfHelper{Uname: "bpf_skb_vlan_push", Enum: BPF_FUNC_skb_vlan_push, Impl: "bpf_skb_vlan_push", Proto: "bpf_skb_vlan_push_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_vlan_pop_proto":                   &BpfHelper{Uname: "bpf_skb_vlan_pop", Enum: BPF_FUNC_skb_vlan_pop, Impl: "bpf_skb_vlan_pop", Proto: "bpf_skb_vlan_pop_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_skb_get_tunnel_key_proto":             &BpfHelper{Uname: "bpf_skb_get_tunnel_key", Enum: BPF_FUNC_skb_get_tunnel_key, Impl: "bpf_skb_get_tunnel_key", Proto: "bpf_skb_get_tunnel_key_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_set_tunnel_key_proto":             &BpfHelper{Uname: "bpf_skb_set_tunnel_key", Enum: BPF_FUNC_skb_set_tunnel_key, Impl: "bpf_skb_set_tunnel_key", Proto: "bpf_skb_set_tunnel_key_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_perf_event_read_proto":                &BpfHelper{Uname: "bpf_perf_event_read", Enum: BPF_FUNC_perf_event_read, Impl: "bpf_perf_event_read", Proto: "bpf_perf_event_read_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_redirect_proto":                       &BpfHelper{Uname: "bpf_redirect", Enum: BPF_FUNC_redirect, Impl: "bpf_redirect", Proto: "bpf_redirect_proto", Args: []string{"ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_xdp_redirect_proto":                   &BpfHelper{Uname: "bpf_redirect", Enum: BPF_FUNC_redirect, Impl: "bpf_xdp_redirect", Proto: "bpf_xdp_redirect_proto", Args: []string{"ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_get_route_realm_proto":                &BpfHelper{Uname: "bpf_get_route_realm", Enum: BPF_FUNC_get_route_realm, Impl: "bpf_get_route_realm", Proto: "bpf_get_route_realm_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_perf_event_output_proto":              &BpfHelper{Uname: "bpf_perf_event_output", Enum: BPF_FUNC_perf_event_output, Impl: "bpf_perf_event_output", Proto: "bpf_perf_event_output_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_event_output_data_proto":              &BpfHelper{Uname: "bpf_perf_event_output", Enum: BPF_FUNC_perf_event_output, Impl: "bpf_event_output_data", Proto: "bpf_event_output_data_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_skb_event_output_proto":               &BpfHelper{Uname: "bpf_perf_event_output", Enum: BPF_FUNC_perf_event_output, Impl: "bpf_skb_event_output", Proto: "bpf_skb_event_output_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_xdp_event_output_proto":               &BpfHelper{Uname: "bpf_perf_event_output", Enum: BPF_FUNC_perf_event_output, Impl: "bpf_xdp_event_output", Proto: "bpf_xdp_event_output_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_perf_event_output_proto_tp":           &BpfHelper{Uname: "bpf_perf_event_output", Enum: BPF_FUNC_perf_event_output, Impl: "bpf_perf_event_output_tp", Proto: "bpf_perf_event_output_proto_tp", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_perf_event_output_proto_raw_tp":       &BpfHelper{Uname: "bpf_perf_event_output", Enum: BPF_FUNC_perf_event_output, Impl: "bpf_perf_event_output_raw_tp", Proto: "bpf_perf_event_output_proto_raw_tp", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_skb_load_bytes_proto":                 &BpfHelper{Uname: "bpf_skb_load_bytes", Enum: BPF_FUNC_skb_load_bytes, Impl: "bpf_skb_load_bytes", Proto: "bpf_skb_load_bytes_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_flow_dissector_load_bytes_proto":      &BpfHelper{Uname: "bpf_skb_load_bytes", Enum: BPF_FUNC_skb_load_bytes, Impl: "bpf_flow_dissector_load_bytes", Proto: "bpf_flow_dissector_load_bytes_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"sk_reuseport_load_bytes_proto":            &BpfHelper{Uname: "bpf_skb_load_bytes", Enum: BPF_FUNC_skb_load_bytes, Impl: "sk_reuseport_load_bytes", Proto: "sk_reuseport_load_bytes_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_get_stackid_proto":                    &BpfHelper{Uname: "bpf_get_stackid", Enum: BPF_FUNC_get_stackid, Impl: "bpf_get_stackid", Proto: "bpf_get_stackid_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_stackid_proto_pe":                 &BpfHelper{Uname: "bpf_get_stackid", Enum: BPF_FUNC_get_stackid, Impl: "bpf_get_stackid_pe", Proto: "bpf_get_stackid_proto_pe", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_get_stackid_proto_tp":                 &BpfHelper{Uname: "bpf_get_stackid", Enum: BPF_FUNC_get_stackid, Impl: "bpf_get_stackid_tp", Proto: "bpf_get_stackid_proto_tp", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_stackid_proto_raw_tp":             &BpfHelper{Uname: "bpf_get_stackid", Enum: BPF_FUNC_get_stackid, Impl: "bpf_get_stackid_raw_tp", Proto: "bpf_get_stackid_proto_raw_tp", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_csum_diff_proto":                      &BpfHelper{Uname: "bpf_csum_diff", Enum: BPF_FUNC_csum_diff, Impl: "bpf_csum_diff", Proto: "bpf_csum_diff_proto", Args: []string{"ARG_PTR_TO_MEM_OR_NULL", "ARG_CONST_SIZE_OR_ZERO", "ARG_PTR_TO_MEM_OR_NULL", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", PktAccess: true},
	"bpf_skb_get_tunnel_opt_proto":             &BpfHelper{Uname: "bpf_skb_get_tunnel_opt", Enum: BPF_FUNC_skb_get_tunnel_opt, Impl: "bpf_skb_get_tunnel_opt", Proto: "bpf_skb_get_tunnel_opt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_skb_set_tunnel_opt_proto":             &BpfHelper{Uname: "bpf_skb_set_tunnel_opt", Enum: BPF_FUNC_skb_set_tunnel_opt, Impl: "bpf_skb_set_tunnel_opt", Proto: "bpf_skb_set_tunnel_opt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_skb_change_proto_proto":               &BpfHelper{Uname: "bpf_skb_change_proto", Enum: BPF_FUNC_skb_change_proto, Impl: "bpf_skb_change_proto", Proto: "bpf_skb_change_proto_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_change_type_proto":                &BpfHelper{Uname: "bpf_skb_change_type", Enum: BPF_FUNC_skb_change_type, Impl: "bpf_skb_change_type", Proto: "bpf_skb_change_type_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_under_cgroup_proto":               &BpfHelper{Uname: "bpf_skb_under_cgroup", Enum: BPF_FUNC_skb_under_cgroup, Impl: "bpf_skb_under_cgroup", Proto: "bpf_skb_under_cgroup_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_get_hash_recalc_proto":                &BpfHelper{Uname: "bpf_get_hash_recalc", Enum: BPF_FUNC_get_hash_recalc, Impl: "bpf_get_hash_recalc", Proto: "bpf_get_hash_recalc_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_current_task_proto":               &BpfHelper{Uname: "bpf_get_current_task", Enum: BPF_FUNC_get_current_task, Impl: "bpf_get_current_task", Proto: "bpf_get_current_task_proto", Ret: "RET_INTEGER", GplOnly: true},
	"bpf_probe_write_user_proto":               &BpfHelper{Uname: "bpf_probe_write_user", Enum: BPF_FUNC_probe_write_user, Impl: "bpf_probe_write_user", Proto: "bpf_probe_write_user_proto", Args: []string{"ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_current_task_under_cgroup_proto":      &BpfHelper{Uname: "bpf_current_task_under_cgroup", Enum: BPF_FUNC_current_task_under_cgroup, Impl: "bpf_current_task_under_cgroup", Proto: "bpf_current_task_under_cgroup_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_change_tail_proto":                &BpfHelper{Uname: "bpf_skb_change_tail", Enum: BPF_FUNC_skb_change_tail, Impl: "bpf_skb_change_tail", Proto: "bpf_skb_change_tail_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"sk_skb_change_tail_proto":                 &BpfHelper{Uname: "bpf_skb_change_tail", Enum: BPF_FUNC_skb_change_tail, Impl: "sk_skb_change_tail", Proto: "sk_skb_change_tail_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_pull_data_proto":                  &BpfHelper{Uname: "bpf_skb_pull_data", Enum: BPF_FUNC_skb_pull_data, Impl: "bpf_skb_pull_data", Proto: "bpf_skb_pull_data_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"sk_skb_pull_data_proto":                   &BpfHelper{Uname: "bpf_skb_pull_data", Enum: BPF_FUNC_skb_pull_data, Impl: "sk_skb_pull_data", Proto: "sk_skb_pull_data_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_csum_update_proto":                    &BpfHelper{Uname: "bpf_csum_update", Enum: BPF_FUNC_csum_update, Impl: "bpf_csum_update", Proto: "bpf_csum_update_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_set_hash_invalid_proto":               &BpfHelper{Uname: "bpf_set_hash_invalid", Enum: BPF_FUNC_set_hash_invalid, Impl: "bpf_set_hash_invalid", Proto: "bpf_set_hash_invalid_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_numa_node_id_proto":               &BpfHelper{Uname: "bpf_get_numa_node_id", Enum: BPF_FUNC_get_numa_node_id, Impl: "bpf_get_numa_node_id", Proto: "bpf_get_numa_node_id_proto", Ret: "RET_INTEGER"},
	"bpf_skb_change_head_proto":                &BpfHelper{Uname: "bpf_skb_change_head", Enum: BPF_FUNC_skb_change_head, Impl: "bpf_skb_change_head", Proto: "bpf_skb_change_head_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"sk_skb_change_head_proto":                 &BpfHelper{Uname: "bpf_skb_change_head", Enum: BPF_FUNC_skb_change_head, Impl: "sk_skb_change_head", Proto: "sk_skb_change_head_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_xdp_adjust_head_proto":                &BpfHelper{Uname: "bpf_xdp_adjust_head", Enum: BPF_FUNC_xdp_adjust_head, Impl: "bpf_xdp_adjust_head", Proto: "bpf_xdp_adjust_head_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_probe_read_compat_str_proto":          &BpfHelper{Uname: "bpf_probe_read_str", Enum: BPF_FUNC_probe_read_str, Impl: "bpf_probe_read_compat_str", Proto: "bpf_probe_read_compat_str_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_socket_cookie_proto":              &BpfHelper{Uname: "bpf_get_socket_cookie", Enum: BPF_FUNC_get_socket_cookie, Impl: "bpf_get_socket_cookie", Proto: "bpf_get_socket_cookie_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_socket_cookie_sock_addr_proto":    &BpfHelper{Uname: "bpf_get_socket_cookie", Enum: BPF_FUNC_get_socket_cookie, Impl: "bpf_get_socket_cookie_sock_addr", Proto: "bpf_get_socket_cookie_sock_addr_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_socket_cookie_sock_proto":         &BpfHelper{Uname: "bpf_get_socket_cookie", Enum: BPF_FUNC_get_socket_cookie, Impl: "bpf_get_socket_cookie_sock", Proto: "bpf_get_socket_cookie_sock_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_socket_cookie_sock_ops_proto":     &BpfHelper{Uname: "bpf_get_socket_cookie", Enum: BPF_FUNC_get_socket_cookie, Impl: "bpf_get_socket_cookie_sock_ops", Proto: "bpf_get_socket_cookie_sock_ops_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_socket_ptr_cookie_proto":          &BpfHelper{Uname: "bpf_get_socket_cookie", Enum: BPF_FUNC_get_socket_cookie, Impl: "bpf_get_socket_ptr_cookie", Proto: "bpf_get_socket_ptr_cookie_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_INTEGER"},
	"bpf_get_socket_uid_proto":                 &BpfHelper{Uname: "bpf_get_socket_uid", Enum: BPF_FUNC_get_socket_uid, Impl: "bpf_get_socket_uid", Proto: "bpf_get_socket_uid_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_set_hash_proto":                       &BpfHelper{Uname: "bpf_set_hash", Enum: BPF_FUNC_set_hash, Impl: "bpf_set_hash", Proto: "bpf_set_hash_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sock_ops_setsockopt_proto":            &BpfHelper{Uname: "bpf_setsockopt", Enum: BPF_FUNC_setsockopt, Impl: "bpf_sock_ops_setsockopt", Proto: "bpf_sock_ops_setsockopt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_sk_setsockopt_proto":                  &BpfHelper{Uname: "bpf_setsockopt", Enum: BPF_FUNC_setsockopt, Impl: "bpf_sk_setsockopt", Proto: "bpf_sk_setsockopt_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_sock_addr_setsockopt_proto":           &BpfHelper{Uname: "bpf_setsockopt", Enum: BPF_FUNC_setsockopt, Impl: "bpf_sock_addr_setsockopt", Proto: "bpf_sock_addr_setsockopt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_skb_adjust_room_proto":                &BpfHelper{Uname: "bpf_skb_adjust_room", Enum: BPF_FUNC_skb_adjust_room, Impl: "bpf_skb_adjust_room", Proto: "bpf_skb_adjust_room_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"sk_skb_adjust_room_proto":                 &BpfHelper{Uname: "bpf_skb_adjust_room", Enum: BPF_FUNC_skb_adjust_room, Impl: "sk_skb_adjust_room", Proto: "sk_skb_adjust_room_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_xdp_redirect_map_proto":               &BpfHelper{Uname: "bpf_redirect_map", Enum: BPF_FUNC_redirect_map, Impl: "bpf_redirect_map", Proto: "bpf_xdp_redirect_map_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sk_redirect_map_proto":                &BpfHelper{Uname: "bpf_sk_redirect_map", Enum: BPF_FUNC_sk_redirect_map, Impl: "bpf_sk_redirect_map", Proto: "bpf_sk_redirect_map_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sock_map_update_proto":                &BpfHelper{Uname: "bpf_sock_map_update", Enum: BPF_FUNC_sock_map_update, Impl: "bpf_sock_map_update", Proto: "bpf_sock_map_update_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_xdp_adjust_meta_proto":                &BpfHelper{Uname: "bpf_xdp_adjust_meta", Enum: BPF_FUNC_xdp_adjust_meta, Impl: "bpf_xdp_adjust_meta", Proto: "bpf_xdp_adjust_meta_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_perf_event_read_value_proto":          &BpfHelper{Uname: "bpf_perf_event_read_value", Enum: BPF_FUNC_perf_event_read_value, Impl: "bpf_perf_event_read_value", Proto: "bpf_perf_event_read_value_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_perf_prog_read_value_proto":           &BpfHelper{Uname: "bpf_perf_prog_read_value", Enum: BPF_FUNC_perf_prog_read_value, Impl: "bpf_perf_prog_read_value", Proto: "bpf_perf_prog_read_value_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_sock_ops_getsockopt_proto":            &BpfHelper{Uname: "bpf_getsockopt", Enum: BPF_FUNC_getsockopt, Impl: "bpf_sock_ops_getsockopt", Proto: "bpf_sock_ops_getsockopt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_sk_getsockopt_proto":                  &BpfHelper{Uname: "bpf_getsockopt", Enum: BPF_FUNC_getsockopt, Impl: "bpf_sk_getsockopt", Proto: "bpf_sk_getsockopt_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_sock_addr_getsockopt_proto":           &BpfHelper{Uname: "bpf_getsockopt", Enum: BPF_FUNC_getsockopt, Impl: "bpf_sock_addr_getsockopt", Proto: "bpf_sock_addr_getsockopt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_override_return_proto":                &BpfHelper{Uname: "bpf_override_return", Enum: BPF_FUNC_override_return, Impl: "bpf_override_return", Proto: "bpf_override_return_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_sock_ops_cb_flags_set_proto":          &BpfHelper{Uname: "bpf_sock_ops_cb_flags_set", Enum: BPF_FUNC_sock_ops_cb_flags_set, Impl: "bpf_sock_ops_cb_flags_set", Proto: "bpf_sock_ops_cb_flags_set_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_msg_redirect_map_proto":               &BpfHelper{Uname: "bpf_msg_redirect_map", Enum: BPF_FUNC_msg_redirect_map, Impl: "bpf_msg_redirect_map", Proto: "bpf_msg_redirect_map_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_msg_apply_bytes_proto":                &BpfHelper{Uname: "bpf_msg_apply_bytes", Enum: BPF_FUNC_msg_apply_bytes, Impl: "bpf_msg_apply_bytes", Proto: "bpf_msg_apply_bytes_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_msg_cork_bytes_proto":                 &BpfHelper{Uname: "bpf_msg_cork_bytes", Enum: BPF_FUNC_msg_cork_bytes, Impl: "bpf_msg_cork_bytes", Proto: "bpf_msg_cork_bytes_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_msg_pull_data_proto":                  &BpfHelper{Uname: "bpf_msg_pull_data", Enum: BPF_FUNC_msg_pull_data, Impl: "bpf_msg_pull_data", Proto: "bpf_msg_pull_data_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_bind_proto":                           &BpfHelper{Uname: "bpf_bind", Enum: BPF_FUNC_bind, Impl: "bpf_bind", Proto: "bpf_bind_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_xdp_adjust_tail_proto":                &BpfHelper{Uname: "bpf_xdp_adjust_tail", Enum: BPF_FUNC_xdp_adjust_tail, Impl: "bpf_xdp_adjust_tail", Proto: "bpf_xdp_adjust_tail_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_get_xfrm_state_proto":             &BpfHelper{Uname: "bpf_skb_get_xfrm_state", Enum: BPF_FUNC_skb_get_xfrm_state, Impl: "bpf_skb_get_xfrm_state", Proto: "bpf_skb_get_xfrm_state_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_get_stack_proto":                      &BpfHelper{Uname: "bpf_get_stack", Enum: BPF_FUNC_get_stack, Impl: "bpf_get_stack", Proto: "bpf_get_stack_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_stack_proto_raw_tp":               &BpfHelper{Uname: "bpf_get_stack", Enum: BPF_FUNC_get_stack, Impl: "bpf_get_stack_raw_tp", Proto: "bpf_get_stack_proto_raw_tp", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_stack_proto_tp":                   &BpfHelper{Uname: "bpf_get_stack", Enum: BPF_FUNC_get_stack, Impl: "bpf_get_stack_tp", Proto: "bpf_get_stack_proto_tp", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_stack_proto_pe":                   &BpfHelper{Uname: "bpf_get_stack", Enum: BPF_FUNC_get_stack, Impl: "bpf_get_stack_pe", Proto: "bpf_get_stack_proto_pe", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_skb_load_bytes_relative_proto":        &BpfHelper{Uname: "bpf_skb_load_bytes_relative", Enum: BPF_FUNC_skb_load_bytes_relative, Impl: "bpf_skb_load_bytes_relative", Proto: "bpf_skb_load_bytes_relative_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"sk_reuseport_load_bytes_relative_proto":   &BpfHelper{Uname: "bpf_skb_load_bytes_relative", Enum: BPF_FUNC_skb_load_bytes_relative, Impl: "sk_reuseport_load_bytes_relative", Proto: "sk_reuseport_load_bytes_relative_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_fib_lookup_proto":                 &BpfHelper{Uname: "bpf_fib_lookup", Enum: BPF_FUNC_fib_lookup, Impl: "bpf_skb_fib_lookup", Proto: "bpf_skb_fib_lookup_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_xdp_fib_lookup_proto":                 &BpfHelper{Uname: "bpf_fib_lookup", Enum: BPF_FUNC_fib_lookup, Impl: "bpf_xdp_fib_lookup", Proto: "bpf_xdp_fib_lookup_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_sock_hash_update_proto":               &BpfHelper{Uname: "bpf_sock_hash_update", Enum: BPF_FUNC_sock_hash_update, Impl: "bpf_sock_hash_update", Proto: "bpf_sock_hash_update_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_msg_redirect_hash_proto":              &BpfHelper{Uname: "bpf_msg_redirect_hash", Enum: BPF_FUNC_msg_redirect_hash, Impl: "bpf_msg_redirect_hash", Proto: "bpf_msg_redirect_hash_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sk_redirect_hash_proto":               &BpfHelper{Uname: "bpf_sk_redirect_hash", Enum: BPF_FUNC_sk_redirect_hash, Impl: "bpf_sk_redirect_hash", Proto: "bpf_sk_redirect_hash_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_lwt_in_push_encap_proto":              &BpfHelper{Uname: "bpf_lwt_push_encap", Enum: BPF_FUNC_lwt_push_encap, Impl: "bpf_lwt_in_push_encap", Proto: "bpf_lwt_in_push_encap_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_lwt_xmit_push_encap_proto":            &BpfHelper{Uname: "bpf_lwt_push_encap", Enum: BPF_FUNC_lwt_push_encap, Impl: "bpf_lwt_xmit_push_encap", Proto: "bpf_lwt_xmit_push_encap_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_lwt_seg6_store_bytes_proto":           &BpfHelper{Uname: "bpf_lwt_seg6_store_bytes", Enum: BPF_FUNC_lwt_seg6_store_bytes, Impl: "bpf_lwt_seg6_store_bytes", Proto: "bpf_lwt_seg6_store_bytes_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_MEM"}, Ret: "RET_INTEGER"},
	"bpf_lwt_seg6_adjust_srh_proto":            &BpfHelper{Uname: "bpf_lwt_seg6_adjust_srh", Enum: BPF_FUNC_lwt_seg6_adjust_srh, Impl: "bpf_lwt_seg6_adjust_srh", Proto: "bpf_lwt_seg6_adjust_srh_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_lwt_seg6_action_proto":                &BpfHelper{Uname: "bpf_lwt_seg6_action", Enum: BPF_FUNC_lwt_seg6_action, Impl: "bpf_lwt_seg6_action", Proto: "bpf_lwt_seg6_action_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"rc_repeat_proto":                          &BpfHelper{Uname: "bpf_rc_repeat", Enum: BPF_FUNC_rc_repeat, Impl: "bpf_rc_repeat", Proto: "rc_repeat_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER", GplOnly: true},
	"rc_keydown_proto":                         &BpfHelper{Uname: "bpf_rc_keydown", Enum: BPF_FUNC_rc_keydown, Impl: "bpf_rc_keydown", Proto: "rc_keydown_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_skb_cgroup_id_proto":                  &BpfHelper{Uname: "bpf_skb_cgroup_id", Enum: BPF_FUNC_skb_cgroup_id, Impl: "bpf_skb_cgroup_id", Proto: "bpf_skb_cgroup_id_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_current_cgroup_id_proto":          &BpfHelper{Uname: "bpf_get_current_cgroup_id", Enum: BPF_FUNC_get_current_cgroup_id, Impl: "bpf_get_current_cgroup_id", Proto: "bpf_get_current_cgroup_id_proto", Ret: "RET_INTEGER"},
	"bpf_get_local_storage_proto":              &BpfHelper{Uname: "bpf_get_local_storage", Enum: BPF_FUNC_get_local_storage, Impl: "bpf_get_local_storage", Proto: "bpf_get_local_storage_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_MAP_VALUE"},
	"sk_select_reuseport_proto":                &BpfHelper{Uname: "bpf_sk_select_reuseport", Enum: BPF_FUNC_sk_select_reuseport, Impl: "sk_select_reuseport", Proto: "sk_select_reuseport_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_KEY", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skb_ancestor_cgroup_id_proto":         &BpfHelper{Uname: "bpf_skb_ancestor_cgroup_id", Enum: BPF_FUNC_skb_ancestor_cgroup_id, Impl: "bpf_skb_ancestor_cgroup_id", Proto: "bpf_skb_ancestor_cgroup_id_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sk_lookup_tcp_proto":                  &BpfHelper{Uname: "bpf_sk_lookup_tcp", Enum: BPF_FUNC_sk_lookup_tcp, Impl: "bpf_sk_lookup_tcp", Proto: "bpf_sk_lookup_tcp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL", PktAccess: true},
	"bpf_xdp_sk_lookup_tcp_proto":              &BpfHelper{Uname: "bpf_sk_lookup_tcp", Enum: BPF_FUNC_sk_lookup_tcp, Impl: "bpf_xdp_sk_lookup_tcp", Proto: "bpf_xdp_sk_lookup_tcp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL", PktAccess: true},
	"bpf_sock_addr_sk_lookup_tcp_proto":        &BpfHelper{Uname: "bpf_sk_lookup_tcp", Enum: BPF_FUNC_sk_lookup_tcp, Impl: "bpf_sock_addr_sk_lookup_tcp", Proto: "bpf_sock_addr_sk_lookup_tcp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL"},
	"bpf_sk_lookup_udp_proto":                  &BpfHelper{Uname: "bpf_sk_lookup_udp", Enum: BPF_FUNC_sk_lookup_udp, Impl: "bpf_sk_lookup_udp", Proto: "bpf_sk_lookup_udp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL", PktAccess: true},
	"bpf_xdp_sk_lookup_udp_proto":              &BpfHelper{Uname: "bpf_sk_lookup_udp", Enum: BPF_FUNC_sk_lookup_udp, Impl: "bpf_xdp_sk_lookup_udp", Proto: "bpf_xdp_sk_lookup_udp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL", PktAccess: true},
	"bpf_sock_addr_sk_lookup_udp_proto":        &BpfHelper{Uname: "bpf_sk_lookup_udp", Enum: BPF_FUNC_sk_lookup_udp, Impl: "bpf_sock_addr_sk_lookup_udp", Proto: "bpf_sock_addr_sk_lookup_udp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL"},
	"bpf_sk_release_proto":                     &BpfHelper{Uname: "bpf_sk_release", Enum: BPF_FUNC_sk_release, Impl: "bpf_sk_release", Proto: "bpf_sk_release_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_INTEGER"},
	"bpf_map_push_elem_proto":                  &BpfHelper{Uname: "bpf_map_push_elem", Enum: BPF_FUNC_map_push_elem, Impl: "bpf_map_push_elem", Proto: "bpf_map_push_elem_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_MAP_VALUE", "ARG_ANYTHING"}, Ret: "RET_INTEGER", PktAccess: true},
	"bpf_map_pop_elem_proto":                   &BpfHelper{Uname: "bpf_map_pop_elem", Enum: BPF_FUNC_map_pop_elem, Impl: "bpf_map_pop_elem", Proto: "bpf_map_pop_elem_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_UNINIT_MAP_VALUE"}, Ret: "RET_INTEGER"},
	"bpf_map_peek_elem_proto":                  &BpfHelper{Uname: "bpf_map_peek_elem", Enum: BPF_FUNC_map_peek_elem, Impl: "bpf_map_peek_elem", Proto: "bpf_map_peek_elem_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_UNINIT_MAP_VALUE"}, Ret: "RET_INTEGER"},
	"bpf_msg_push_data_proto":                  &BpfHelper{Uname: "bpf_msg_push_data", Enum: BPF_FUNC_msg_push_data, Impl: "bpf_msg_push_data", Proto: "bpf_msg_push_data_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_msg_pop_data_proto":                   &BpfHelper{Uname: "bpf_msg_pop_data", Enum: BPF_FUNC_msg_pop_data, Impl: "bpf_msg_pop_data", Proto: "bpf_msg_pop_data_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"rc_pointer_rel_proto":                     &BpfHelper{Uname: "bpf_rc_pointer_rel", Enum: BPF_FUNC_rc_pointer_rel, Impl: "bpf_rc_pointer_rel", Proto: "rc_pointer_rel_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_spin_lock_proto":                      &BpfHelper{Uname: "bpf_spin_lock", Enum: BPF_FUNC_spin_lock, Impl: "bpf_spin_lock", Proto: "bpf_spin_lock_proto", Args: []string{"ARG_PTR_TO_SPIN_LOCK"}, Ret: "RET_VOID"},
	"bpf_spin_unlock_proto":                    &BpfHelper{Uname: "bpf_spin_unlock", Enum: BPF_FUNC_spin_unlock, Impl: "bpf_spin_unlock", Proto: "bpf_spin_unlock_proto", Args: []string{"ARG_PTR_TO_SPIN_LOCK"}, Ret: "RET_VOID"},
	"bpf_sk_fullsock_proto":                    &BpfHelper{Uname: "bpf_sk_fullsock", Enum: BPF_FUNC_sk_fullsock, Impl: "bpf_sk_fullsock", Proto: "bpf_sk_fullsock_proto", Args: []string{"ARG_PTR_TO_SOCK_COMMON"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL"},
	"bpf_tcp_sock_proto":                       &BpfHelper{Uname: "bpf_tcp_sock", Enum: BPF_FUNC_tcp_sock, Impl: "bpf_tcp_sock", Proto: "bpf_tcp_sock_proto", Args: []string{"ARG_PTR_TO_SOCK_COMMON"}, Ret: "RET_PTR_TO_TCP_SOCK_OR_NULL"},
	"bpf_skb_ecn_set_ce_proto":                 &BpfHelper{Uname: "bpf_skb_ecn_set_ce", Enum: BPF_FUNC_skb_ecn_set_ce, Impl: "bpf_skb_ecn_set_ce", Proto: "bpf_skb_ecn_set_ce_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_listener_sock_proto":              &BpfHelper{Uname: "bpf_get_listener_sock", Enum: BPF_FUNC_get_listener_sock, Impl: "bpf_get_listener_sock", Proto: "bpf_get_listener_sock_proto", Args: []string{"ARG_PTR_TO_SOCK_COMMON"}, Ret: "RET_PTR_TO_SOCKET_OR_NULL"},
	"bpf_skc_lookup_tcp_proto":                 &BpfHelper{Uname: "bpf_skc_lookup_tcp", Enum: BPF_FUNC_skc_lookup_tcp, Impl: "bpf_skc_lookup_tcp", Proto: "bpf_skc_lookup_tcp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCK_COMMON_OR_NULL", PktAccess: true},
	"bpf_xdp_skc_lookup_tcp_proto":             &BpfHelper{Uname: "bpf_skc_lookup_tcp", Enum: BPF_FUNC_skc_lookup_tcp, Impl: "bpf_xdp_skc_lookup_tcp", Proto: "bpf_xdp_skc_lookup_tcp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCK_COMMON_OR_NULL", PktAccess: true},
	"bpf_sock_addr_skc_lookup_tcp_proto":       &BpfHelper{Uname: "bpf_skc_lookup_tcp", Enum: BPF_FUNC_skc_lookup_tcp, Impl: "bpf_sock_addr_skc_lookup_tcp", Proto: "bpf_sock_addr_skc_lookup_tcp_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_SOCK_COMMON_OR_NULL"},
	"bpf_tcp_check_syncookie_proto":            &BpfHelper{Uname: "bpf_tcp_check_syncookie", Enum: BPF_FUNC_tcp_check_syncookie, Impl: "bpf_tcp_check_syncookie", Proto: "bpf_tcp_check_syncookie_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER", GplOnly: true, PktAccess: true},
	"bpf_sysctl_get_name_proto":                &BpfHelper{Uname: "bpf_sysctl_get_name", Enum: BPF_FUNC_sysctl_get_name, Impl: "bpf_sysctl_get_name", Proto: "bpf_sysctl_get_name_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sysctl_get_current_value_proto":       &BpfHelper{Uname: "bpf_sysctl_get_current_value", Enum: BPF_FUNC_sysctl_get_current_value, Impl: "bpf_sysctl_get_current_value", Proto: "bpf_sysctl_get_current_value_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_sysctl_get_new_value_proto":           &BpfHelper{Uname: "bpf_sysctl_get_new_value", Enum: BPF_FUNC_sysctl_get_new_value, Impl: "bpf_sysctl_get_new_value", Proto: "bpf_sysctl_get_new_value_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_sysctl_set_new_value_proto":           &BpfHelper{Uname: "bpf_sysctl_set_new_value", Enum: BPF_FUNC_sysctl_set_new_value, Impl: "bpf_sysctl_set_new_value", Proto: "bpf_sysctl_set_new_value_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_strtol_proto":                         &BpfHelper{Uname: "bpf_strtol", Enum: BPF_FUNC_strtol, Impl: "bpf_strtol", Proto: "bpf_strtol_proto", Args: []string{"ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_PTR_TO_LONG"}, Ret: "RET_INTEGER"},
	"bpf_strtoul_proto":                        &BpfHelper{Uname: "bpf_strtoul", Enum: BPF_FUNC_strtoul, Impl: "bpf_strtoul", Proto: "bpf_strtoul_proto", Args: []string{"ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_PTR_TO_LONG"}, Ret: "RET_INTEGER"},
	"bpf_sk_storage_get_proto":                 &BpfHelper{Uname: "bpf_sk_storage_get", Enum: BPF_FUNC_sk_storage_get, Impl: "bpf_sk_storage_get", Proto: "bpf_sk_storage_get_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID_SOCK_COMMON", "ARG_PTR_TO_MAP_VALUE_OR_NULL", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_MAP_VALUE_OR_NULL"},
	"bpf_sk_storage_get_cg_sock_proto":         &BpfHelper{Uname: "bpf_sk_storage_get", Enum: BPF_FUNC_sk_storage_get, Impl: "bpf_sk_storage_get", Proto: "bpf_sk_storage_get_cg_sock_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_CTX", "ARG_PTR_TO_MAP_VALUE_OR_NULL", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_MAP_VALUE_OR_NULL"},
	"bpf_sk_storage_get_tracing_proto":         &BpfHelper{Uname: "bpf_sk_storage_get", Enum: BPF_FUNC_sk_storage_get, Impl: "bpf_sk_storage_get_tracing", Proto: "bpf_sk_storage_get_tracing_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_MAP_VALUE_OR_NULL", "ARG_ANYTHING"}, ArgBtfIds: []string{"struct sock_common"}, Ret: "RET_PTR_TO_MAP_VALUE_OR_NULL"},
	"bpf_sk_storage_delete_proto":              &BpfHelper{Uname: "bpf_sk_storage_delete", Enum: BPF_FUNC_sk_storage_delete, Impl: "bpf_sk_storage_delete", Proto: "bpf_sk_storage_delete_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_INTEGER"},
	"bpf_sk_storage_delete_tracing_proto":      &BpfHelper{Uname: "bpf_sk_storage_delete", Enum: BPF_FUNC_sk_storage_delete, Impl: "bpf_sk_storage_delete_tracing", Proto: "bpf_sk_storage_delete_tracing_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID"}, ArgBtfIds: []string{"struct sock_common"}, Ret: "RET_INTEGER"},
	"bpf_send_signal_proto":                    &BpfHelper{Uname: "bpf_send_signal", Enum: BPF_FUNC_send_signal, Impl: "bpf_send_signal", Proto: "bpf_send_signal_proto", Args: []string{"ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_tcp_gen_syncookie_proto":              &BpfHelper{Uname: "bpf_tcp_gen_syncookie", Enum: BPF_FUNC_tcp_gen_syncookie, Impl: "bpf_tcp_gen_syncookie", Proto: "bpf_tcp_gen_syncookie_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER", GplOnly: true, PktAccess: true},
	"bpf_skb_output_proto":                     &BpfHelper{Uname: "bpf_skb_output", Enum: BPF_FUNC_skb_output, Impl: "bpf_skb_event_output", Proto: "bpf_skb_output_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, ArgBtfIds: []string{"struct sk_buff"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_probe_read_user_proto":                &BpfHelper{Uname: "bpf_probe_read_user", Enum: BPF_FUNC_probe_read_user, Impl: "bpf_probe_read_user", Proto: "bpf_probe_read_user_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_probe_read_kernel_proto":              &BpfHelper{Uname: "bpf_probe_read_kernel", Enum: BPF_FUNC_probe_read_kernel, Impl: "bpf_probe_read_kernel", Proto: "bpf_probe_read_kernel_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_probe_read_user_str_proto":            &BpfHelper{Uname: "bpf_probe_read_user_str", Enum: BPF_FUNC_probe_read_user_str, Impl: "bpf_probe_read_user_str", Proto: "bpf_probe_read_user_str_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_probe_read_kernel_str_proto":          &BpfHelper{Uname: "bpf_probe_read_kernel_str", Enum: BPF_FUNC_probe_read_kernel_str, Impl: "bpf_probe_read_kernel_str", Proto: "bpf_probe_read_kernel_str_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_tcp_send_ack_proto":                   &BpfHelper{Uname: "bpf_tcp_send_ack", Enum: BPF_FUNC_tcp_send_ack, Impl: "bpf_tcp_send_ack", Proto: "bpf_tcp_send_ack_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_send_signal_thread_proto":             &BpfHelper{Uname: "bpf_send_signal_thread", Enum: BPF_FUNC_send_signal_thread, Impl: "bpf_send_signal_thread", Proto: "bpf_send_signal_thread_proto", Args: []string{"ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_jiffies64_proto":                      &BpfHelper{Uname: "bpf_jiffies64", Enum: BPF_FUNC_jiffies64, Impl: "bpf_jiffies64", Proto: "bpf_jiffies64_proto", Ret: "RET_INTEGER"},
	"bpf_read_branch_records_proto":            &BpfHelper{Uname: "bpf_read_branch_records", Enum: BPF_FUNC_read_branch_records, Impl: "bpf_read_branch_records", Proto: "bpf_read_branch_records_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM_OR_NULL", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_ns_current_pid_tgid_proto":        &BpfHelper{Uname: "bpf_get_ns_current_pid_tgid", Enum: BPF_FUNC_get_ns_current_pid_tgid, Impl: "bpf_get_ns_current_pid_tgid", Proto: "bpf_get_ns_current_pid_tgid_proto", Args: []string{"ARG_ANYTHING", "ARG_ANYTHING", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_xdp_output_proto":                     &BpfHelper{Uname: "bpf_xdp_output", Enum: BPF_FUNC_xdp_output, Impl: "bpf_xdp_event_output", Proto: "bpf_xdp_output_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_CONST_MAP_PTR", "ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, ArgBtfIds: []string{"struct xdp_buff"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_netns_cookie_sock_addr_proto":     &BpfHelper{Uname: "bpf_get_netns_cookie", Enum: BPF_FUNC_get_netns_cookie, Impl: "bpf_get_netns_cookie_sock_addr", Proto: "bpf_get_netns_cookie_sock_addr_proto", Args: []string{"ARG_PTR_TO_CTX_OR_NULL"}, Ret: "RET_INTEGER"},
	"bpf_get_netns_cookie_sock_proto":          &BpfHelper{Uname: "bpf_get_netns_cookie", Enum: BPF_FUNC_get_netns_cookie, Impl: "bpf_get_netns_cookie_sock", Proto: "bpf_get_netns_cookie_sock_proto", Args: []string{"ARG_PTR_TO_CTX_OR_NULL"}, Ret: "RET_INTEGER"},
	"bpf_get_netns_cookie_sock_ops_proto":      &BpfHelper{Uname: "bpf_get_netns_cookie", Enum: BPF_FUNC_get_netns_cookie, Impl: "bpf_get_netns_cookie_sock_ops", Proto: "bpf_get_netns_cookie_sock_ops_proto", Args: []string{"ARG_PTR_TO_CTX_OR_NULL"}, Ret: "RET_INTEGER"},
	"bpf_get_netns_cookie_sk_msg_proto":        &BpfHelper{Uname: "bpf_get_netns_cookie", Enum: BPF_FUNC_get_netns_cookie, Impl: "bpf_get_netns_cookie_sk_msg", Proto: "bpf_get_netns_cookie_sk_msg_proto", Args: []string{"ARG_PTR_TO_CTX_OR_NULL"}, Ret: "RET_INTEGER"},
	"bpf_get_netns_cookie_sockopt_proto":       &BpfHelper{Uname: "bpf_get_netns_cookie", Enum: BPF_FUNC_get_netns_cookie, Impl: "bpf_get_netns_cookie_sockopt", Proto: "bpf_get_netns_cookie_sockopt_proto", Args: []string{"ARG_PTR_TO_CTX_OR_NULL"}, Ret: "RET_INTEGER"},
	"bpf_get_current_ancestor_cgroup_id_proto": &BpfHelper{Uname: "bpf_get_current_ancestor_cgroup_id", Enum: BPF_FUNC_get_current_ancestor_cgroup_id, Impl: "bpf_get_current_ancestor_cgroup_id", Proto: "bpf_get_current_ancestor_cgroup_id_proto", Args: []string{"ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sk_assign_proto":                      &BpfHelper{Uname: "bpf_sk_assign", Enum: BPF_FUNC_sk_assign, Impl: "bpf_sk_assign", Proto: "bpf_sk_assign_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_BTF_ID_SOCK_COMMON", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sk_lookup_assign_proto":               &BpfHelper{Uname: "bpf_sk_assign", Enum: BPF_FUNC_sk_assign, Impl: "bpf_sk_lookup_assign", Proto: "bpf_sk_lookup_assign_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_SOCKET_OR_NULL", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_ktime_get_boot_ns_proto":              &BpfHelper{Uname: "bpf_ktime_get_boot_ns", Enum: BPF_FUNC_ktime_get_boot_ns, Impl: "bpf_ktime_get_boot_ns", Proto: "bpf_ktime_get_boot_ns_proto", Ret: "RET_INTEGER"},
	"bpf_seq_printf_proto":                     &BpfHelper{Uname: "bpf_seq_printf", Enum: BPF_FUNC_seq_printf, Impl: "bpf_seq_printf", Proto: "bpf_seq_printf_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_PTR_TO_MEM_OR_NULL", "ARG_CONST_SIZE_OR_ZERO"}, ArgBtfIds: []string{"struct seq_file"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_seq_write_proto":                      &BpfHelper{Uname: "bpf_seq_write", Enum: BPF_FUNC_seq_write, Impl: "bpf_seq_write", Proto: "bpf_seq_write_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, ArgBtfIds: []string{"struct seq_file"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_sk_cgroup_id_proto":                   &BpfHelper{Uname: "bpf_sk_cgroup_id", Enum: BPF_FUNC_sk_cgroup_id, Impl: "bpf_sk_cgroup_id", Proto: "bpf_sk_cgroup_id_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_INTEGER"},
	"bpf_sk_ancestor_cgroup_id_proto":          &BpfHelper{Uname: "bpf_sk_ancestor_cgroup_id", Enum: BPF_FUNC_sk_ancestor_cgroup_id, Impl: "bpf_sk_ancestor_cgroup_id", Proto: "bpf_sk_ancestor_cgroup_id_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_ringbuf_output_proto":                 &BpfHelper{Uname: "bpf_ringbuf_output", Enum: BPF_FUNC_ringbuf_output, Impl: "bpf_ringbuf_output", Proto: "bpf_ringbuf_output_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_ringbuf_reserve_proto":                &BpfHelper{Uname: "bpf_ringbuf_reserve", Enum: BPF_FUNC_ringbuf_reserve, Impl: "bpf_ringbuf_reserve", Proto: "bpf_ringbuf_reserve_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_CONST_ALLOC_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_ALLOC_MEM_OR_NULL"},
	"bpf_ringbuf_submit_proto":                 &BpfHelper{Uname: "bpf_ringbuf_submit", Enum: BPF_FUNC_ringbuf_submit, Impl: "bpf_ringbuf_submit", Proto: "bpf_ringbuf_submit_proto", Args: []string{"ARG_PTR_TO_ALLOC_MEM", "ARG_ANYTHING"}, Ret: "RET_VOID"},
	"bpf_ringbuf_discard_proto":                &BpfHelper{Uname: "bpf_ringbuf_discard", Enum: BPF_FUNC_ringbuf_discard, Impl: "bpf_ringbuf_discard", Proto: "bpf_ringbuf_discard_proto", Args: []string{"ARG_PTR_TO_ALLOC_MEM", "ARG_ANYTHING"}, Ret: "RET_VOID"},
	"bpf_ringbuf_query_proto":                  &BpfHelper{Uname: "bpf_ringbuf_query", Enum: BPF_FUNC_ringbuf_query, Impl: "bpf_ringbuf_query", Proto: "bpf_ringbuf_query_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_csum_level_proto":                     &BpfHelper{Uname: "bpf_csum_level", Enum: BPF_FUNC_csum_level, Impl: "bpf_csum_level", Proto: "bpf_csum_level_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_skc_to_tcp6_sock_proto":               &BpfHelper{Uname: "bpf_skc_to_tcp6_sock", Enum: BPF_FUNC_skc_to_tcp6_sock, Impl: "bpf_skc_to_tcp6_sock", Proto: "bpf_skc_to_tcp6_sock_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_PTR_TO_BTF_ID_OR_NULL", RetBtfId: "struct tcp6_sock"},
	"bpf_skc_to_tcp_sock_proto":                &BpfHelper{Uname: "bpf_skc_to_tcp_sock", Enum: BPF_FUNC_skc_to_tcp_sock, Impl: "bpf_skc_to_tcp_sock", Proto: "bpf_skc_to_tcp_sock_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_PTR_TO_BTF_ID_OR_NULL", RetBtfId: "struct tcp_sock"},
	"bpf_skc_to_tcp_timewait_sock_proto":       &BpfHelper{Uname: "bpf_skc_to_tcp_timewait_sock", Enum: BPF_FUNC_skc_to_tcp_timewait_sock, Impl: "bpf_skc_to_tcp_timewait_sock", Proto: "bpf_skc_to_tcp_timewait_sock_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_PTR_TO_BTF_ID_OR_NULL", RetBtfId: "struct tcp_timewait_sock"},
	"bpf_skc_to_tcp_request_sock_proto":        &BpfHelper{Uname: "bpf_skc_to_tcp_request_sock", Enum: BPF_FUNC_skc_to_tcp_request_sock, Impl: "bpf_skc_to_tcp_request_sock", Proto: "bpf_skc_to_tcp_request_sock_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_PTR_TO_BTF_ID_OR_NULL", RetBtfId: "struct tcp_request_sock"},
	"bpf_skc_to_udp6_sock_proto":               &BpfHelper{Uname: "bpf_skc_to_udp6_sock", Enum: BPF_FUNC_skc_to_udp6_sock, Impl: "bpf_skc_to_udp6_sock", Proto: "bpf_skc_to_udp6_sock_proto", Args: []string{"ARG_PTR_TO_BTF_ID_SOCK_COMMON"}, Ret: "RET_PTR_TO_BTF_ID_OR_NULL", RetBtfId: "struct udp6_sock"},
	"bpf_get_task_stack_proto":                 &BpfHelper{Uname: "bpf_get_task_stack", Enum: BPF_FUNC_get_task_stack, Impl: "bpf_get_task_stack", Proto: "bpf_get_task_stack_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, ArgBtfIds: []string{"struct task_struct"}, Ret: "RET_INTEGER"},
	"bpf_sock_ops_load_hdr_opt_proto":          &BpfHelper{Uname: "bpf_load_hdr_opt", Enum: BPF_FUNC_load_hdr_opt, Impl: "bpf_sock_ops_load_hdr_opt", Proto: "bpf_sock_ops_load_hdr_opt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sock_ops_store_hdr_opt_proto":         &BpfHelper{Uname: "bpf_store_hdr_opt", Enum: BPF_FUNC_store_hdr_opt, Impl: "bpf_sock_ops_store_hdr_opt", Proto: "bpf_sock_ops_store_hdr_opt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sock_ops_reserve_hdr_opt_proto":       &BpfHelper{Uname: "bpf_reserve_hdr_opt", Enum: BPF_FUNC_reserve_hdr_opt, Impl: "bpf_sock_ops_reserve_hdr_opt", Proto: "bpf_sock_ops_reserve_hdr_opt_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_inode_storage_get_proto":              &BpfHelper{Uname: "bpf_inode_storage_get", Enum: BPF_FUNC_inode_storage_get, Impl: "bpf_inode_storage_get", Proto: "bpf_inode_storage_get_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_MAP_VALUE_OR_NULL", "ARG_ANYTHING"}, ArgBtfIds: []string{"struct inode"}, Ret: "RET_PTR_TO_MAP_VALUE_OR_NULL"},
	"bpf_inode_storage_delete_proto":           &BpfHelper{Uname: "bpf_inode_storage_delete", Enum: BPF_FUNC_inode_storage_delete, Impl: "bpf_inode_storage_delete", Proto: "bpf_inode_storage_delete_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID"}, ArgBtfIds: []string{"struct inode"}, Ret: "RET_INTEGER"},
	"bpf_d_path_proto":                         &BpfHelper{Uname: "bpf_d_path", Enum: BPF_FUNC_d_path, Impl: "bpf_d_path", Proto: "bpf_d_path_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO"}, ArgBtfIds: []string{"struct path"}, Ret: "RET_INTEGER"},
	"bpf_copy_from_user_proto":                 &BpfHelper{Uname: "bpf_copy_from_user", Enum: BPF_FUNC_copy_from_user, Impl: "bpf_copy_from_user", Proto: "bpf_copy_from_user_proto", Args: []string{"ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_snprintf_btf_proto":                   &BpfHelper{Uname: "bpf_snprintf_btf", Enum: BPF_FUNC_snprintf_btf, Impl: "bpf_snprintf_btf", Proto: "bpf_snprintf_btf_proto", Args: []string{"ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_seq_printf_btf_proto":                 &BpfHelper{Uname: "bpf_seq_printf_btf", Enum: BPF_FUNC_seq_printf_btf, Impl: "bpf_seq_printf_btf", Proto: "bpf_seq_printf_btf_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, ArgBtfIds: []string{"struct seq_file"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_skb_cgroup_classid_proto":             &BpfHelper{Uname: "bpf_skb_cgroup_classid", Enum: BPF_FUNC_skb_cgroup_classid, Impl: "bpf_skb_cgroup_classid", Proto: "bpf_skb_cgroup_classid_proto", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_redirect_neigh_proto":                 &BpfHelper{Uname: "bpf_redirect_neigh", Enum: BPF_FUNC_redirect_neigh, Impl: "bpf_redirect_neigh", Proto: "bpf_redirect_neigh_proto", Args: []string{"ARG_ANYTHING", "ARG_PTR_TO_MEM_OR_NULL", "ARG_CONST_SIZE_OR_ZERO", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_per_cpu_ptr_proto":                    &BpfHelper{Uname: "bpf_per_cpu_ptr", Enum: BPF_FUNC_per_cpu_ptr, Impl: "bpf_per_cpu_ptr", Proto: "bpf_per_cpu_ptr_proto", Args: []string{"ARG_PTR_TO_PERCPU_BTF_ID", "ARG_ANYTHING"}, Ret: "RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL"},
	"bpf_this_cpu_ptr_proto":                   &BpfHelper{Uname: "bpf_this_cpu_ptr", Enum: BPF_FUNC_this_cpu_ptr, Impl: "bpf_this_cpu_ptr", Proto: "bpf_this_cpu_ptr_proto", Args: []string{"ARG_PTR_TO_PERCPU_BTF_ID"}, Ret: "RET_PTR_TO_MEM_OR_BTF_ID"},
	"bpf_redirect_peer_proto":                  &BpfHelper{Uname: "bpf_redirect_peer", Enum: BPF_FUNC_redirect_peer, Impl: "bpf_redirect_peer", Proto: "bpf_redirect_peer_proto", Args: []string{"ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_task_storage_get_proto":               &BpfHelper{Uname: "bpf_task_storage_get", Enum: BPF_FUNC_task_storage_get, Impl: "bpf_task_storage_get", Proto: "bpf_task_storage_get_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_MAP_VALUE_OR_NULL", "ARG_ANYTHING"}, ArgBtfIds: []string{"struct task_struct"}, Ret: "RET_PTR_TO_MAP_VALUE_OR_NULL"},
	"bpf_task_storage_delete_proto":            &BpfHelper{Uname: "bpf_task_storage_delete", Enum: BPF_FUNC_task_storage_delete, Impl: "bpf_task_storage_delete", Proto: "bpf_task_storage_delete_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_BTF_ID"}, ArgBtfIds: []string{"struct task_struct"}, Ret: "RET_INTEGER"},
	"bpf_get_current_task_btf_proto":           &BpfHelper{Uname: "bpf_get_current_task_btf", Enum: BPF_FUNC_get_current_task_btf, Impl: "bpf_get_current_task_btf", Proto: "bpf_get_current_task_btf_proto", Ret: "RET_PTR_TO_BTF_ID", RetBtfId: "struct task_struct", GplOnly: true},
	"bpf_bprm_opts_set_proto":                  &BpfHelper{Uname: "bpf_bprm_opts_set", Enum: BPF_FUNC_bprm_opts_set, Impl: "bpf_bprm_opts_set", Proto: "bpf_bprm_opts_set_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_ktime_get_coarse_ns_proto":            &BpfHelper{Uname: "bpf_ktime_get_coarse_ns", Enum: BPF_FUNC_ktime_get_coarse_ns, Impl: "bpf_ktime_get_coarse_ns", Proto: "bpf_ktime_get_coarse_ns_proto", Ret: "RET_INTEGER"},
	"bpf_ima_inode_hash_proto":                 &BpfHelper{Uname: "bpf_ima_inode_hash", Enum: BPF_FUNC_ima_inode_hash, Impl: "bpf_ima_inode_hash", Proto: "bpf_ima_inode_hash_proto", Args: []string{"ARG_PTR_TO_BTF_ID", "ARG_PTR_TO_UNINIT_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_sock_from_file_proto":                 &BpfHelper{Uname: "bpf_sock_from_file", Enum: BPF_FUNC_sock_from_file, Impl: "bpf_sock_from_file", Proto: "bpf_sock_from_file_proto", Args: []string{"ARG_PTR_TO_BTF_ID"}, ArgBtfIds: []string{"struct file"}, Ret: "RET_PTR_TO_BTF_ID_OR_NULL", RetBtfId: "struct socket"},
	"bpf_skb_check_mtu_proto":                  &BpfHelper{Uname: "bpf_check_mtu", Enum: BPF_FUNC_check_mtu, Impl: "bpf_skb_check_mtu", Proto: "bpf_skb_check_mtu_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_INT", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_xdp_check_mtu_proto":                  &BpfHelper{Uname: "bpf_check_mtu", Enum: BPF_FUNC_check_mtu, Impl: "bpf_xdp_check_mtu", Proto: "bpf_xdp_check_mtu_proto", Args: []string{"ARG_PTR_TO_CTX", "ARG_ANYTHING", "ARG_PTR_TO_INT", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_for_each_map_elem_proto":              &BpfHelper{Uname: "bpf_for_each_map_elem", Enum: BPF_FUNC_for_each_map_elem, Impl: "bpf_for_each_map_elem", Proto: "bpf_for_each_map_elem_proto", Args: []string{"ARG_CONST_MAP_PTR", "ARG_PTR_TO_FUNC", "ARG_PTR_TO_STACK_OR_NULL", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_snprintf_proto":                       &BpfHelper{Uname: "bpf_snprintf", Enum: BPF_FUNC_snprintf, Impl: "bpf_snprintf", Proto: "bpf_snprintf_proto", Args: []string{"ARG_PTR_TO_MEM_OR_NULL", "ARG_CONST_SIZE_OR_ZERO", "ARG_PTR_TO_CONST_STR", "ARG_PTR_TO_MEM_OR_NULL", "ARG_CONST_SIZE_OR_ZERO"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_sys_bpf_proto":                        &BpfHelper{Uname: "bpf_sys_bpf", Enum: BPF_FUNC_sys_bpf, Impl: "bpf_sys_bpf", Proto: "bpf_sys_bpf_proto", Args: []string{"ARG_ANYTHING", "ARG_PTR_TO_MEM", "ARG_CONST_SIZE"}, Ret: "RET_INTEGER"},
	"bpf_btf_find_by_name_kind_proto":          &BpfHelper{Uname: "bpf_btf_find_by_name_kind", Enum: BPF_FUNC_btf_find_by_name_kind, Impl: "bpf_btf_find_by_name_kind", Proto: "bpf_btf_find_by_name_kind_proto", Args: []string{"ARG_PTR_TO_MEM", "ARG_CONST_SIZE", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_sys_close_proto":                      &BpfHelper{Uname: "bpf_sys_close", Enum: BPF_FUNC_sys_close, Impl: "bpf_sys_close", Proto: "bpf_sys_close_proto", Args: []string{"ARG_ANYTHING"}, Ret: "RET_INTEGER"},
	"bpf_timer_init_proto":                     &BpfHelper{Uname: "bpf_timer_init", Enum: BPF_FUNC_timer_init, Impl: "bpf_timer_init", Proto: "bpf_timer_init_proto", Args: []string{"ARG_PTR_TO_TIMER", "ARG_CONST_MAP_PTR", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_timer_set_callback_proto":             &BpfHelper{Uname: "bpf_timer_set_callback", Enum: BPF_FUNC_timer_set_callback, Impl: "bpf_timer_set_callback", Proto: "bpf_timer_set_callback_proto", Args: []string{"ARG_PTR_TO_TIMER", "ARG_PTR_TO_FUNC"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_timer_start_proto":                    &BpfHelper{Uname: "bpf_timer_start", Enum: BPF_FUNC_timer_start, Impl: "bpf_timer_start", Proto: "bpf_timer_start_proto", Args: []string{"ARG_PTR_TO_TIMER", "ARG_ANYTHING", "ARG_ANYTHING"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_timer_cancel_proto":                   &BpfHelper{Uname: "bpf_timer_cancel", Enum: BPF_FUNC_timer_cancel, Impl: "bpf_timer_cancel", Proto: "bpf_timer_cancel_proto", Args: []string{"ARG_PTR_TO_TIMER"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_func_ip_proto_kprobe":             &BpfHelper{Uname: "bpf_get_func_ip", Enum: BPF_FUNC_get_func_ip, Impl: "bpf_get_func_ip_kprobe", Proto: "bpf_get_func_ip_proto_kprobe", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_func_ip_proto_tracing":            &BpfHelper{Uname: "bpf_get_func_ip", Enum: BPF_FUNC_get_func_ip, Impl: "bpf_get_func_ip_tracing", Proto: "bpf_get_func_ip_proto_tracing", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER", GplOnly: true},
	"bpf_get_attach_cookie_proto_trace":        &BpfHelper{Uname: "bpf_get_attach_cookie", Enum: BPF_FUNC_get_attach_cookie, Impl: "bpf_get_attach_cookie_trace", Proto: "bpf_get_attach_cookie_proto_trace", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_get_attach_cookie_proto_pe":           &BpfHelper{Uname: "bpf_get_attach_cookie", Enum: BPF_FUNC_get_attach_cookie, Impl: "bpf_get_attach_cookie_pe", Proto: "bpf_get_attach_cookie_proto_pe", Args: []string{"ARG_PTR_TO_CTX"}, Ret: "RET_INTEGER"},
	"bpf_task_pt_regs_proto":                   &BpfHelper{Uname: "bpf_task_pt_regs", Enum: BPF_FUNC_task_pt_regs, Impl: "bpf_task_pt_regs", Proto: "bpf_task_pt_regs_proto", Args: []string{"ARG_PTR_TO_BTF_ID"}, ArgBtfIds: []string{"struct task_struct"}, Ret: "RET_PTR_TO_BTF_ID", RetBtfId: "struct pt_regs", GplOnly: true},
}

var ProgTypeMap = map[BpfProgTypeEnum]*BpfProgType{
	BPF_PROG_TYPE_SOCK_OPS: &BpfProgType{
		Name: "sock_ops",
		User: "struct bpf_sock_ops",
		Kern: "struct bpf_sock_ops_kern",
		Enum: BPF_PROG_TYPE_SOCK_OPS,
		SecDefs: []SecDef{
			SecDef{"sockops", nil, false},
		},
		FuncProtos: []string{
			"bpf_sock_ops_setsockopt_proto", "bpf_sock_ops_getsockopt_proto", "bpf_sock_ops_cb_flags_set_proto", "bpf_sock_map_update_proto",
			"bpf_sock_hash_update_proto", "bpf_get_socket_cookie_sock_ops_proto", "bpf_get_local_storage_proto", "bpf_event_output_data_proto",
			"bpf_sk_storage_get_proto", "bpf_sk_storage_delete_proto", "bpf_get_netns_cookie_sock_ops_proto", "bpf_sock_ops_load_hdr_opt_proto",
			"bpf_sock_ops_store_hdr_opt_proto", "bpf_sock_ops_reserve_hdr_opt_proto", "bpf_tcp_sock_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_LIRC_MODE2: &BpfProgType{
		Name: "lirc_mode2",
		User: "__u32",
		Kern: "u32",
		Enum: BPF_PROG_TYPE_LIRC_MODE2,
		SecDefs: []SecDef{
			SecDef{"lirc_mode2", nil, false},
		},
		FuncProtos: []string{
			"rc_repeat_proto", "rc_keydown_proto", "rc_pointer_rel_proto", "bpf_map_lookup_elem_proto",
			"bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto", "bpf_map_pop_elem_proto",
			"bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto", "bpf_tail_call_proto",
			"bpf_get_prandom_u32_proto",
			"bpf_trace_printk_proto",
	}},
	BPF_PROG_TYPE_SK_REUSEPORT: &BpfProgType{
		Name: "sk_reuseport",
		User: "struct sk_reuseport_md",
		Kern: "struct sk_reuseport_kern",
		Enum: BPF_PROG_TYPE_SK_REUSEPORT,
		SecDefs: []SecDef{
			SecDef{"sk_reuseport/migrate", nil, false},
			SecDef{"sk_reuseport", nil, false},
		},
		FuncProtos: []string{
			"sk_select_reuseport_proto", "sk_reuseport_load_bytes_proto", "sk_reuseport_load_bytes_relative_proto", "bpf_get_socket_ptr_cookie_proto",
			"bpf_ktime_get_coarse_ns_proto",
			//bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_SK_MSG: &BpfProgType{
		Name: "sk_msg",
		User: "struct sk_msg_md",
		Kern: "struct sk_msg",
		Enum: BPF_PROG_TYPE_SK_MSG,
		SecDefs: []SecDef{
			SecDef{"sk_msg", nil, false},
		},
		FuncProtos: []string{
			"bpf_msg_redirect_map_proto", "bpf_msg_redirect_hash_proto", "bpf_msg_apply_bytes_proto", "bpf_msg_cork_bytes_proto",
			"bpf_msg_pull_data_proto", "bpf_msg_push_data_proto", "bpf_msg_pop_data_proto", "bpf_event_output_data_proto",
			"bpf_get_current_uid_gid_proto", "bpf_get_current_pid_tgid_proto", "bpf_sk_storage_get_proto", "bpf_sk_storage_delete_proto",
			"bpf_get_netns_cookie_sk_msg_proto", "bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_get_cgroup_classid_curr_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_FLOW_DISSECTOR: &BpfProgType{
		Name: "flow_dissector",
		User: "struct __sk_buff",
		Kern: "struct bpf_flow_dissector",
		Enum: BPF_PROG_TYPE_FLOW_DISSECTOR,
		SecDefs: []SecDef{
			SecDef{"flow_dissector", nil, false},
		},
		FuncProtos: []string{
			"bpf_flow_dissector_load_bytes_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_SOCKET_FILTER: &BpfProgType{
		Name: "sk_filter",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_SOCKET_FILTER,
		SecDefs: []SecDef{
			SecDef{"socket", nil, false},
		},
		FuncProtos: []string{
			"bpf_skb_load_bytes_proto",
			"bpf_skb_load_bytes_relative_proto",
			"bpf_get_socket_cookie_proto",
			"bpf_get_socket_uid_proto",
			"bpf_skb_event_output_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_CGROUP_SKB: &BpfProgType{
		Name: "cg_skb",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_CGROUP_SKB,
		SecDefs: []SecDef{
			SecDef{"cgroup_skb/ingress", nil, false},
			SecDef{"cgroup_skb/egress", nil, false},
			SecDef{"cgroup/skb", nil, false},
		},
		FuncProtos: []string{
			"bpf_get_local_storage_proto", "bpf_sk_fullsock_proto", "bpf_sk_storage_get_proto", "bpf_sk_storage_delete_proto",
			"bpf_skb_event_output_proto", "bpf_skb_cgroup_id_proto", "bpf_skb_ancestor_cgroup_id_proto", "bpf_sk_cgroup_id_proto",
			"bpf_sk_ancestor_cgroup_id_proto", "bpf_sk_lookup_tcp_proto", "bpf_sk_lookup_udp_proto", "bpf_sk_release_proto",
			"bpf_skc_lookup_tcp_proto", "bpf_tcp_sock_proto", "bpf_get_listener_sock_proto", "bpf_skb_ecn_set_ce_proto",
			//sk_filter_func_proto
			"bpf_skb_load_bytes_proto", "bpf_skb_load_bytes_relative_proto", "bpf_get_socket_cookie_proto", "bpf_get_socket_uid_proto",
			"bpf_skb_event_output_proto",
			//  bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//    bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_CGROUP_SOCK: &BpfProgType{
		Name: "cg_sock",
		User: "struct bpf_sock",
		Kern: "struct sock",
		Enum: BPF_PROG_TYPE_CGROUP_SOCK,
		SecDefs: []SecDef{
			SecDef{"cgroup/sock_create", nil, false},
			SecDef{"cgroup/sock_release", nil, false},
			SecDef{"cgroup/sock", nil, false},
			SecDef{"cgroup/post_bind4", nil, false},
			SecDef{"cgroup/post_bind6", nil, false},
		},
		FuncProtos: []string{
			"bpf_get_current_uid_gid_proto", "bpf_get_local_storage_proto", "bpf_get_socket_cookie_sock_proto", "bpf_get_netns_cookie_sock_proto",
			"bpf_event_output_data_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_comm_proto", "bpf_get_current_cgroup_id_proto",
			"bpf_get_current_ancestor_cgroup_id_proto", "bpf_get_cgroup_classid_curr_proto", "bpf_sk_storage_get_cg_sock_proto",
			"bpf_ktime_get_coarse_ns_proto",
			//bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_LWT_IN: &BpfProgType{
		Name: "lwt_in",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_LWT_IN,
		SecDefs: []SecDef{
			SecDef{"lwt_in", nil, false},
		},
		FuncProtos: []string{
			"bpf_lwt_in_push_encap_proto",
			//lwt_out_func_proto
			"bpf_skb_load_bytes_proto", "bpf_skb_pull_data_proto", "bpf_csum_diff_proto", "bpf_get_cgroup_classid_proto",
			"bpf_get_route_realm_proto", "bpf_get_hash_recalc_proto", "bpf_skb_event_output_proto", "bpf_get_smp_processor_id_proto",
			"bpf_skb_under_cgroup_proto",
			//  bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//    bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_LWT_SEG6LOCAL: &BpfProgType{
		Name: "lwt_seg6local",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_LWT_SEG6LOCAL,
		SecDefs: []SecDef{
			SecDef{"lwt_seg6local", nil, false},
		},
		FuncProtos: []string{
			"bpf_lwt_seg6_store_bytes_proto", "bpf_lwt_seg6_action_proto", "bpf_lwt_seg6_adjust_srh_proto",
			//lwt_out_func_proto
			"bpf_skb_load_bytes_proto", "bpf_skb_pull_data_proto", "bpf_csum_diff_proto", "bpf_get_cgroup_classid_proto",
			"bpf_get_route_realm_proto", "bpf_get_hash_recalc_proto", "bpf_skb_event_output_proto", "bpf_get_smp_processor_id_proto",
			"bpf_skb_under_cgroup_proto",
			//  bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//    bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_SK_SKB: &BpfProgType{
		Name: "sk_skb",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_SK_SKB,
		SecDefs: []SecDef{
			SecDef{"sk_skb/stream_parser", nil, false},
			SecDef{"sk_skb/stream_verdict", nil, false},
			SecDef{"sk_skb", nil, false},
		},
		FuncProtos: []string{
			"bpf_skb_store_bytes_proto", "bpf_skb_load_bytes_proto", "sk_skb_pull_data_proto", "sk_skb_change_tail_proto",
			"sk_skb_change_head_proto", "sk_skb_adjust_room_proto", "bpf_get_socket_cookie_proto", "bpf_get_socket_uid_proto",
			"bpf_sk_redirect_map_proto", "bpf_sk_redirect_hash_proto", "bpf_skb_event_output_proto", "bpf_sk_lookup_tcp_proto",
			"bpf_sk_lookup_udp_proto", "bpf_sk_release_proto", "bpf_skc_lookup_tcp_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_RAW_TRACEPOINT: &BpfProgType{
		Name: "raw_tracepoint",
		User: "struct bpf_raw_tracepoint_args",
		Kern: "u64",
		Enum: BPF_PROG_TYPE_RAW_TRACEPOINT,
		SecDefs: []SecDef{
			SecDef{"raw_tracepoint/", GenRawTracepointEntry, false},
			SecDef{"raw_tp/", GenRawTracepointEntry, false},
		},
		FuncProtos: []string{
			"bpf_perf_event_output_proto_raw_tp", "bpf_get_stackid_proto_raw_tp", "bpf_get_stack_proto_raw_tp",
			//bpf_tracing_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_tail_call_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto",
			"bpf_task_pt_regs_proto", "bpf_get_current_uid_gid_proto", "bpf_get_current_comm_proto", "bpf_trace_printk_proto",
			"bpf_get_smp_processor_id_proto", "bpf_get_numa_node_id_proto", "bpf_perf_event_read_proto", "bpf_current_task_under_cgroup_proto",
			"bpf_get_prandom_u32_proto", "bpf_probe_write_user_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_probe_read_compat_proto", "bpf_probe_read_compat_str_proto",
			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_send_signal_proto", "bpf_send_signal_thread_proto",
			"bpf_perf_event_read_value_proto", "bpf_get_ns_current_pid_tgid_proto", "bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto",
			"bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto", "bpf_ringbuf_query_proto", "bpf_jiffies64_proto",
			"bpf_get_task_stack_proto", "bpf_copy_from_user_proto", "bpf_snprintf_btf_proto", "bpf_per_cpu_ptr_proto",
			"bpf_this_cpu_ptr_proto", "bpf_task_storage_get_proto", "bpf_task_storage_delete_proto", "bpf_for_each_map_elem_proto",
			"bpf_snprintf_proto", /*"bpf_get_func_ip_proto_tracing",*/ "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_timer_init_proto", "bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto",
	}},
	BPF_PROG_TYPE_CGROUP_DEVICE: &BpfProgType{
		Name: "cg_dev",
		User: "struct bpf_cgroup_dev_ctx",
		Kern: "struct bpf_cgroup_dev_ctx",
		Enum: BPF_PROG_TYPE_CGROUP_DEVICE,
		SecDefs: []SecDef{
			SecDef{"cgroup/dev", nil, false},
		},
		FuncProtos: []string{
			"bpf_get_current_uid_gid_proto", "bpf_get_local_storage_proto", "bpf_get_current_cgroup_id_proto", "bpf_event_output_data_proto",
			//bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_CGROUP_SOCKOPT: &BpfProgType{
		Name: "cg_sockopt",
		User: "struct bpf_sockopt",
		Kern: "struct bpf_sockopt_kern",
		Enum: BPF_PROG_TYPE_CGROUP_SOCKOPT,
		SecDefs: []SecDef{
			SecDef{"cgroup/getsockopt", nil, false},
			SecDef{"cgroup/setsockopt", nil, false},
		},
		FuncProtos: []string{
			"bpf_get_netns_cookie_sockopt_proto", "bpf_sk_storage_get_proto", "bpf_sk_storage_delete_proto", "bpf_sk_setsockopt_proto",
			"bpf_sk_getsockopt_proto", "bpf_tcp_sock_proto",
			//cgroup_base_func_proto
			"bpf_get_current_uid_gid_proto", "bpf_get_local_storage_proto", "bpf_get_current_cgroup_id_proto", "bpf_event_output_data_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_SK_LOOKUP: &BpfProgType{
		Name: "sk_lookup",
		User: "struct bpf_sk_lookup",
		Kern: "struct bpf_sk_lookup_kern",
		Enum: BPF_PROG_TYPE_SK_LOOKUP,
		SecDefs: []SecDef{
			SecDef{"sk_lookup", nil, false},
		},
		FuncProtos: []string{
			"bpf_event_output_data_proto", "bpf_sk_lookup_assign_proto", "bpf_sk_release_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_SCHED_CLS: &BpfProgType{
		Name: "tc_cls",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_SCHED_CLS,
		SecDefs: []SecDef{
			SecDef{"tc", nil, false},
			SecDef{"classifier", nil, false},
		},
		FuncProtos: []string{
			"bpf_skb_store_bytes_proto", "bpf_skb_load_bytes_proto", "bpf_skb_load_bytes_relative_proto", "bpf_skb_pull_data_proto",
			"bpf_csum_diff_proto", "bpf_csum_update_proto", "bpf_csum_level_proto", "bpf_l3_csum_replace_proto",
			"bpf_l4_csum_replace_proto", "bpf_clone_redirect_proto", "bpf_get_cgroup_classid_proto", "bpf_skb_vlan_push_proto",
			"bpf_skb_vlan_pop_proto", "bpf_skb_change_proto_proto", "bpf_skb_change_type_proto", "bpf_skb_adjust_room_proto",
			"bpf_skb_change_tail_proto", "bpf_skb_change_head_proto", "bpf_skb_get_tunnel_key_proto", "bpf_skb_set_tunnel_key_proto",
			"bpf_skb_get_tunnel_opt_proto", "bpf_skb_set_tunnel_opt_proto", "bpf_redirect_proto", "bpf_redirect_neigh_proto",
			"bpf_redirect_peer_proto", "bpf_get_route_realm_proto", "bpf_get_hash_recalc_proto", "bpf_set_hash_invalid_proto",
			"bpf_set_hash_proto", "bpf_skb_event_output_proto", "bpf_get_smp_processor_id_proto", "bpf_skb_under_cgroup_proto",
			"bpf_get_socket_cookie_proto", "bpf_get_socket_uid_proto", "bpf_skb_fib_lookup_proto", "bpf_skb_check_mtu_proto",
			"bpf_sk_fullsock_proto", "bpf_sk_storage_get_proto", "bpf_sk_storage_delete_proto", "bpf_skb_get_xfrm_state_proto",
			"bpf_skb_cgroup_classid_proto", "bpf_skb_cgroup_id_proto", "bpf_skb_ancestor_cgroup_id_proto", "bpf_sk_lookup_tcp_proto",
			"bpf_sk_lookup_udp_proto", "bpf_sk_release_proto", "bpf_tcp_sock_proto", "bpf_get_listener_sock_proto",
			"bpf_skc_lookup_tcp_proto", "bpf_tcp_check_syncookie_proto", "bpf_skb_ecn_set_ce_proto", "bpf_tcp_gen_syncookie_proto",
			"bpf_sk_assign_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_SCHED_ACT: &BpfProgType{
		Name: "tc_act",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_SCHED_ACT,
		SecDefs: []SecDef{
			SecDef{"action", nil, false},
		},
		FuncProtos: []string{
			"bpf_skb_store_bytes_proto", "bpf_skb_load_bytes_proto", "bpf_skb_load_bytes_relative_proto", "bpf_skb_pull_data_proto",
			"bpf_csum_diff_proto", "bpf_csum_update_proto", "bpf_csum_level_proto", "bpf_l3_csum_replace_proto",
			"bpf_l4_csum_replace_proto", "bpf_clone_redirect_proto", "bpf_get_cgroup_classid_proto", "bpf_skb_vlan_push_proto",
			"bpf_skb_vlan_pop_proto", "bpf_skb_change_proto_proto", "bpf_skb_change_type_proto", "bpf_skb_adjust_room_proto",
			"bpf_skb_change_tail_proto", "bpf_skb_change_head_proto", "bpf_skb_get_tunnel_key_proto", "bpf_skb_set_tunnel_key_proto",
			"bpf_skb_get_tunnel_opt_proto", "bpf_skb_set_tunnel_opt_proto", "bpf_redirect_proto", "bpf_redirect_neigh_proto",
			"bpf_redirect_peer_proto", "bpf_get_route_realm_proto", "bpf_get_hash_recalc_proto", "bpf_set_hash_invalid_proto",
			"bpf_set_hash_proto", "bpf_skb_event_output_proto", "bpf_get_smp_processor_id_proto", "bpf_skb_under_cgroup_proto",
			"bpf_get_socket_cookie_proto", "bpf_get_socket_uid_proto", "bpf_skb_fib_lookup_proto", "bpf_skb_check_mtu_proto",
			"bpf_sk_fullsock_proto", "bpf_sk_storage_get_proto", "bpf_sk_storage_delete_proto", "bpf_skb_get_xfrm_state_proto",
			"bpf_skb_cgroup_classid_proto", "bpf_skb_cgroup_id_proto", "bpf_skb_ancestor_cgroup_id_proto", "bpf_sk_lookup_tcp_proto",
			"bpf_sk_lookup_udp_proto", "bpf_sk_release_proto", "bpf_tcp_sock_proto", "bpf_get_listener_sock_proto",
			"bpf_skc_lookup_tcp_proto", "bpf_tcp_check_syncookie_proto", "bpf_skb_ecn_set_ce_proto", "bpf_tcp_gen_syncookie_proto",
			"bpf_sk_assign_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR: &BpfProgType{
		Name: "cg_sock_addr",
		User: "struct bpf_sock_addr",
		Kern: "struct bpf_sock_addr_kern",
		Enum: BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
		SecDefs: []SecDef{
			SecDef{"cgroup/bind4", nil, false},
			SecDef{"cgroup/bind6", nil, false},
			SecDef{"cgroup/connect4", nil, false},
			SecDef{"cgroup/connect6", nil, false},
			SecDef{"cgroup/sendmsg4", nil, false},
			SecDef{"cgroup/sendmsg6", nil, false},
			SecDef{"cgroup/recvmsg4", nil, false},
			SecDef{"cgroup/recvmsg6", nil, false},
			SecDef{"cgroup/getpeername4", nil, false},
			SecDef{"cgroup/getpeername6", nil, false},
			SecDef{"cgroup/getsockname4", nil, false},
			SecDef{"cgroup/getsockname6", nil, false},
		},
		FuncProtos: []string{
			"bpf_get_current_uid_gid_proto", "bpf_bind_proto", "bpf_get_socket_cookie_sock_addr_proto", "bpf_get_netns_cookie_sock_addr_proto",
			"bpf_get_local_storage_proto", "bpf_event_output_data_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_comm_proto",
			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_get_cgroup_classid_curr_proto", "bpf_sock_addr_sk_lookup_tcp_proto",
			"bpf_sock_addr_sk_lookup_udp_proto", "bpf_sk_release_proto", "bpf_sock_addr_skc_lookup_tcp_proto", "bpf_sk_storage_get_proto",
			"bpf_sk_storage_delete_proto", "bpf_sock_addr_setsockopt_proto", "bpf_sock_addr_getsockopt_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_PERF_EVENT: &BpfProgType{
		Name: "perf_event",
		User: "struct bpf_perf_event_data",
		Kern: "struct bpf_perf_event_data_kern",
		Enum: BPF_PROG_TYPE_PERF_EVENT,
		SecDefs: []SecDef{
			SecDef{"perf_event", nil, false},
		},
		FuncProtos: []string{
			"bpf_perf_event_output_proto_tp", "bpf_get_stackid_proto_pe", "bpf_get_stack_proto_pe", "bpf_perf_prog_read_value_proto",
			"bpf_read_branch_records_proto", "bpf_get_attach_cookie_proto_pe",
			//bpf_tracing_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_tail_call_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto",
			"bpf_task_pt_regs_proto", "bpf_get_current_uid_gid_proto", "bpf_get_current_comm_proto", "bpf_trace_printk_proto",
			"bpf_get_smp_processor_id_proto", "bpf_get_numa_node_id_proto", "bpf_perf_event_read_proto", "bpf_current_task_under_cgroup_proto",
			"bpf_get_prandom_u32_proto", "bpf_probe_write_user_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_probe_read_compat_proto", "bpf_probe_read_compat_str_proto",
			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_send_signal_proto", "bpf_send_signal_thread_proto",
			"bpf_perf_event_read_value_proto", "bpf_get_ns_current_pid_tgid_proto", "bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto",
			"bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto", "bpf_ringbuf_query_proto", "bpf_jiffies64_proto",
			"bpf_get_task_stack_proto", "bpf_copy_from_user_proto", "bpf_snprintf_btf_proto", "bpf_per_cpu_ptr_proto",
			"bpf_this_cpu_ptr_proto", "bpf_task_storage_get_proto", "bpf_task_storage_delete_proto", "bpf_for_each_map_elem_proto",
			"bpf_snprintf_proto", /*"bpf_get_func_ip_proto_tracing",*/ "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_timer_init_proto", "bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto",
	}},
	BPF_PROG_TYPE_CGROUP_SYSCTL: &BpfProgType{
		Name: "cg_sysctl",
		User: "struct bpf_sysctl",
		Kern: "struct bpf_sysctl_kern",
		Enum: BPF_PROG_TYPE_CGROUP_SYSCTL,
		SecDefs: []SecDef{
			SecDef{"cgroup/sysctl", nil, false},
		},
		FuncProtos: []string{
			"bpf_strtol_proto", "bpf_strtoul_proto", "bpf_sysctl_get_name_proto", "bpf_sysctl_get_current_value_proto", "bpf_sysctl_get_new_value_proto",
			"bpf_sysctl_set_new_value_proto", "bpf_ktime_get_coarse_ns_proto",
			//cgroup_base_func_proto
			"bpf_get_current_uid_gid_proto", "bpf_get_local_storage_proto", "bpf_get_current_cgroup_id_proto", "bpf_event_output_data_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_XDP: &BpfProgType{
		Name: "xdp",
		User: "struct xdp_md",
		Kern: "struct xdp_buff",
		Enum: BPF_PROG_TYPE_XDP,
		SecDefs: []SecDef{
//			SecDef{"xdp.frags/devmap", nil, false},
			//SecDef{"xdp/devmap", nil, false}, //XXX to be supported
			//SecDef{"xdp_devmap/", GenXdpEntry, false},
//			SecDef{"xdp.frags/cpumap", nil, false},
			//SecDef{"xdp/cpumap", nil, false}, //XXX to be supported
			//SecDef{"xdp_cpumap/", GenXdpEntry, false},
//			SecDef{"xdp.frags", nil, false},
			SecDef{"xdp", nil, false},
		},
		FuncProtos: []string{
			"bpf_xdp_event_output_proto", "bpf_get_smp_processor_id_proto", "bpf_csum_diff_proto", "bpf_xdp_adjust_head_proto",
			"bpf_xdp_adjust_meta_proto", "bpf_xdp_redirect_proto", "bpf_xdp_redirect_map_proto", "bpf_xdp_adjust_tail_proto",
			"bpf_xdp_fib_lookup_proto", "bpf_xdp_check_mtu_proto", "bpf_xdp_sk_lookup_udp_proto", "bpf_xdp_sk_lookup_tcp_proto",
			"bpf_sk_release_proto", "bpf_xdp_skc_lookup_tcp_proto", "bpf_tcp_check_syncookie_proto", "bpf_tcp_gen_syncookie_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_LWT_OUT: &BpfProgType{
		Name: "lwt_out",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_LWT_OUT,
		SecDefs: []SecDef{
			SecDef{"lwt_out", nil, false},
		},
		FuncProtos: []string{
			"bpf_skb_load_bytes_proto", "bpf_skb_pull_data_proto", "bpf_csum_diff_proto", "bpf_get_cgroup_classid_proto",
			"bpf_get_route_realm_proto", "bpf_get_hash_recalc_proto", "bpf_skb_event_output_proto", "bpf_get_smp_processor_id_proto",
			"bpf_skb_under_cgroup_proto",
			//bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//  bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_LWT_XMIT: &BpfProgType{
		Name: "lwt_xmit",
		User: "struct __sk_buff",
		Kern: "struct sk_buff",
		Enum: BPF_PROG_TYPE_LWT_XMIT,
		SecDefs: []SecDef{
			SecDef{"lwt_xmit", nil, false},
		},
		FuncProtos: []string{
			"bpf_skb_get_tunnel_key_proto", "bpf_skb_set_tunnel_key_proto", "bpf_skb_get_tunnel_opt_proto", "bpf_skb_set_tunnel_opt_proto",
			"bpf_redirect_proto", "bpf_clone_redirect_proto", "bpf_skb_change_tail_proto", "bpf_skb_change_head_proto",
			"bpf_skb_store_bytes_proto", "bpf_csum_update_proto", "bpf_csum_level_proto", "bpf_l3_csum_replace_proto",
			"bpf_l4_csum_replace_proto", "bpf_set_hash_invalid_proto", "bpf_lwt_xmit_push_encap_proto",
			//lwt_out_func_proto
			"bpf_skb_load_bytes_proto", "bpf_skb_pull_data_proto", "bpf_csum_diff_proto", "bpf_get_cgroup_classid_proto",
			"bpf_get_route_realm_proto", "bpf_get_hash_recalc_proto", "bpf_skb_event_output_proto", "bpf_get_smp_processor_id_proto",
			"bpf_skb_under_cgroup_proto",
			//  bpf_sk_base_func_proto
			"bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto", "bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto",
			"bpf_skc_to_udp6_sock_proto", "bpf_ktime_get_coarse_ns_proto",
			//    bpf_base_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto", "bpf_timer_init_proto",
			"bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto", "bpf_trace_printk_proto",
			"bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto", "bpf_snprintf_proto",
			"bpf_task_pt_regs_proto",
	}},
	BPF_PROG_TYPE_KPROBE: &BpfProgType{
		Name: "kprobe",
		User: "struct bpf_user_pt_regs_t",
		Kern: "struct pt_regs",
		Enum: BPF_PROG_TYPE_KPROBE,
		SecDefs: []SecDef{
			SecDef{"kprobe/", GenKprobeEntry, false},
			SecDef{"uprobe/", GenKprobeEntry, false},
			SecDef{"kretprobe/", GenKprobeEntry, false},
			SecDef{"uretprobe/", GenKprobeEntry, false},
		},
		FuncProtos: []string{
			"bpf_perf_event_output_proto", "bpf_get_stackid_proto", "bpf_get_stack_proto", "bpf_override_return_proto",
			"bpf_get_attach_cookie_proto_trace", "bpf_get_func_ip_proto_kprobe",
			//bpf_tracing_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_tail_call_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto",
			"bpf_task_pt_regs_proto", "bpf_get_current_uid_gid_proto", "bpf_get_current_comm_proto", "bpf_trace_printk_proto",
			"bpf_get_smp_processor_id_proto", "bpf_get_numa_node_id_proto", "bpf_perf_event_read_proto", "bpf_current_task_under_cgroup_proto",
			"bpf_get_prandom_u32_proto", "bpf_probe_write_user_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_probe_read_compat_proto", "bpf_probe_read_compat_str_proto",
			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_send_signal_proto", "bpf_send_signal_thread_proto",
			"bpf_perf_event_read_value_proto", "bpf_get_ns_current_pid_tgid_proto", "bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto",
			"bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto", "bpf_ringbuf_query_proto", "bpf_jiffies64_proto",
			"bpf_get_task_stack_proto", "bpf_copy_from_user_proto", "bpf_snprintf_btf_proto", "bpf_per_cpu_ptr_proto",
			"bpf_this_cpu_ptr_proto", "bpf_task_storage_get_proto", "bpf_task_storage_delete_proto", "bpf_for_each_map_elem_proto",
			"bpf_snprintf_proto", "bpf_get_func_ip_proto_tracing", "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_timer_init_proto", "bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto",
	}},
	BPF_PROG_TYPE_TRACEPOINT: &BpfProgType{
		Name: "tracepoint",
		User: "__u64",
		Kern: "u64",
		Enum: BPF_PROG_TYPE_TRACEPOINT,
		SecDefs: []SecDef{
			SecDef{"tracepoint/", GenTracepointEntry, false},
			SecDef{"tp/", GenTracepointEntry, false},
		},
		FuncProtos: []string{
			"bpf_perf_event_output_proto_tp", "bpf_get_stackid_proto_tp", "bpf_get_stack_proto_tp", "bpf_get_attach_cookie_proto_trace",
			//bpf_tracing_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_tail_call_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto",
			"bpf_task_pt_regs_proto", "bpf_get_current_uid_gid_proto", "bpf_get_current_comm_proto", "bpf_trace_printk_proto",
			"bpf_get_smp_processor_id_proto", "bpf_get_numa_node_id_proto", "bpf_perf_event_read_proto", "bpf_current_task_under_cgroup_proto",
			"bpf_get_prandom_u32_proto", "bpf_probe_write_user_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_probe_read_compat_proto", "bpf_probe_read_compat_str_proto",
			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_send_signal_proto", "bpf_send_signal_thread_proto",
			"bpf_perf_event_read_value_proto", "bpf_get_ns_current_pid_tgid_proto", "bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto",
			"bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto", "bpf_ringbuf_query_proto", "bpf_jiffies64_proto",
			"bpf_get_task_stack_proto", "bpf_copy_from_user_proto", "bpf_snprintf_btf_proto", "bpf_per_cpu_ptr_proto",
			"bpf_this_cpu_ptr_proto", "bpf_task_storage_get_proto", "bpf_task_storage_delete_proto", "bpf_for_each_map_elem_proto",
			"bpf_snprintf_proto", /*"bpf_get_func_ip_proto_tracing",*/ "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_timer_init_proto", "bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto",
	}},
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: &BpfProgType{
		Name: "raw_tracepoint_writable",
		User: "struct bpf_raw_tracepoint_args",
		Kern: "u64",
		Enum: BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
		SecDefs: []SecDef{
			SecDef{"raw_tracepoint.w/", GenRawTracepointEntry, false},
			SecDef{"raw_tp.w/", GenRawTracepointEntry, false},
		},
		FuncProtos: []string{
			"bpf_perf_event_output_proto_raw_tp", "bpf_get_stackid_proto_raw_tp", "bpf_get_stack_proto",
			//bpf_tracing_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_tail_call_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto",
			"bpf_task_pt_regs_proto", "bpf_get_current_uid_gid_proto", "bpf_get_current_comm_proto", "bpf_trace_printk_proto",
			"bpf_get_smp_processor_id_proto", "bpf_get_numa_node_id_proto", "bpf_perf_event_read_proto", "bpf_current_task_under_cgroup_proto",
			"bpf_get_prandom_u32_proto", "bpf_probe_write_user_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_probe_read_compat_proto", "bpf_probe_read_compat_str_proto",
			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_send_signal_proto", "bpf_send_signal_thread_proto",
			"bpf_perf_event_read_value_proto", "bpf_get_ns_current_pid_tgid_proto", "bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto",
			"bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto", "bpf_ringbuf_query_proto", "bpf_jiffies64_proto",
			"bpf_get_task_stack_proto", "bpf_copy_from_user_proto", "bpf_snprintf_btf_proto", "bpf_per_cpu_ptr_proto",
			"bpf_this_cpu_ptr_proto", "bpf_task_storage_get_proto", "bpf_task_storage_delete_proto", "bpf_for_each_map_elem_proto",
			"bpf_snprintf_proto", /*"bpf_get_func_ip_proto_tracing",*/ "bpf_spin_lock_proto", "bpf_spin_unlock_proto",
			"bpf_timer_init_proto", "bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto",
	}},
	BPF_PROG_TYPE_TRACING: &BpfProgType{
		Name: "tracing",
		User: "void *",
		Kern: "void *",
		Enum: BPF_PROG_TYPE_TRACING,
		SecDefs: []SecDef{
			SecDef{"tp_btf/", nil, false},
			SecDef{"fentry/", GenBPFTrampoline, false},
			SecDef{"fmod_ret", GenBPFTrampoline, false},
			SecDef{"fexit/", GenBPFTrampoline, false},
			SecDef{"fentry.s/", GenBPFTrampoline, true},
			SecDef{"fmod_ret.s/", GenBPFTrampoline, true},
			SecDef{"fexit.s/", GenBPFTrampoline, true},
			SecDef{"iter/", GenTracingIter, false},
			SecDef{"iter.s/", GenTracingIter, true},
		},
		FuncProtos: []string{
			"bpf_skb_output_proto", "bpf_xdp_output_proto", "bpf_skc_to_tcp6_sock_proto", "bpf_skc_to_tcp_sock_proto",
			"bpf_skc_to_tcp_timewait_sock_proto", "bpf_skc_to_tcp_request_sock_proto", "bpf_skc_to_udp6_sock_proto", "bpf_sk_storage_get_tracing_proto",
			"bpf_sk_storage_delete_tracing_proto", "bpf_sock_from_file_proto", "bpf_get_socket_ptr_cookie_proto", "bpf_seq_printf_proto",
			"bpf_seq_write_proto", "bpf_seq_printf_btf_proto", "bpf_d_path_proto",
			//raw_tp_prog_func_proto
			"bpf_perf_event_output_proto_raw_tp", "bpf_get_stackid_proto_raw_tp", "bpf_get_stack_proto_raw_tp",
			//  bpf_tracing_func_proto
			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			"bpf_tail_call_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto",
			"bpf_task_pt_regs_proto", "bpf_get_current_uid_gid_proto", "bpf_get_current_comm_proto", "bpf_trace_printk_proto",
			"bpf_get_smp_processor_id_proto", "bpf_get_numa_node_id_proto", "bpf_perf_event_read_proto", "bpf_current_task_under_cgroup_proto",
			"bpf_get_prandom_u32_proto", "bpf_probe_write_user_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_probe_read_compat_proto", "bpf_probe_read_compat_str_proto",
			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_send_signal_proto", "bpf_send_signal_thread_proto",
			"bpf_perf_event_read_value_proto", "bpf_get_ns_current_pid_tgid_proto", "bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto",
			"bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto", "bpf_ringbuf_query_proto", "bpf_jiffies64_proto",
			"bpf_get_task_stack_proto", "bpf_copy_from_user_proto", "bpf_snprintf_btf_proto", "bpf_per_cpu_ptr_proto",
			"bpf_this_cpu_ptr_proto", "bpf_task_storage_get_proto", "bpf_task_storage_delete_proto", "bpf_for_each_map_elem_proto",
			"bpf_snprintf_proto", "bpf_get_func_ip_proto_tracing",
			//    bpf_base_func_proto
			//"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
			//"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_get_prandom_u32_proto", "bpf_get_raw_smp_processor_id_proto",
			//"bpf_get_numa_node_id_proto", "bpf_tail_call_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
			//"bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto", "bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto",
			//"bpf_ringbuf_query_proto", "bpf_for_each_map_elem_proto", "bpf_spin_lock_proto",
			"bpf_spin_unlock_proto",
			//"bpf_jiffies64_proto", "bpf_per_cpu_ptr_proto", "bpf_this_cpu_ptr_proto",
			"bpf_timer_init_proto", "bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto",
			//"bpf_trace_printk_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto", "bpf_probe_read_user_proto",
			//"bpf_probe_read_kernel_proto", "bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_snprintf_btf_proto",
			//"bpf_snprintf_proto", "bpf_task_pt_regs_proto",
	}},
//	BPF_PROG_TYPE_STRUCT_OPS: &BpfProgType{
//		Name: "bpf_struct_ops",
//		User: "void *",
//		Kern: "void *",
//		Enum: BPF_PROG_TYPE_STRUCT_OPS,
//		SecDefs: []SecDef{
//			SecDef{"struct_ops+", nil, false}
//		},
//		FuncProtos: []string{//XXX: why missing this prog type
//	}},
//	BPF_PROG_TYPE_EXT: &BpfProgType{
//		Name: "bpf_extension",
//		User: "void *",
//		Kern: "void *",
//		Enum: BPF_PROG_TYPE_EXT,
//		SecDefs: []SecDef{
//			SecDef{"freplace/", nil, false}
//		},
//		FuncProtos: []string{//XXX: why missing this prog type
//	}},
//	BPF_PROG_TYPE_LSM: &BpfProgType{
//		Name: "lsm",
//		User: "void *",
//		Kern: "void *",
//		Enum: BPF_PROG_TYPE_LSM,
//		SecDefs: []SecDef{
//			SecDef{"lsm/", nil, false},
//			SecDef{"lsm.s/", nil, true},
//		},
//		FuncProtos: []string{//XXX: why missing this prog type
//			"bpf_inode_storage_get_proto","bpf_inode_storage_delete_proto","bpf_sk_storage_get_proto", "bpf_sk_storage_delete_proto",
//			"bpf_spin_lock_proto", "bpf_spin_unlock_proto", "bpf_bprm_opts_set_proto", "bpf_ima_inode_hash_proto",
//			//bpf_tracing_func_proto
//			"bpf_map_lookup_elem_proto", "bpf_map_update_elem_proto", "bpf_map_delete_elem_proto", "bpf_map_push_elem_proto",
//			"bpf_map_pop_elem_proto", "bpf_map_peek_elem_proto", "bpf_ktime_get_ns_proto", "bpf_ktime_get_boot_ns_proto",
//			"bpf_tail_call_proto", "bpf_get_current_pid_tgid_proto", "bpf_get_current_task_proto", "bpf_get_current_task_btf_proto",
//			"bpf_task_pt_regs_proto", "bpf_get_current_uid_gid_proto", "bpf_get_current_comm_proto", "bpf_trace_printk_proto",
//			"bpf_get_smp_processor_id_proto", "bpf_get_numa_node_id_proto", "bpf_perf_event_read_proto", "bpf_current_task_under_cgroup_proto",
//			"bpf_get_prandom_u32_proto", "bpf_probe_write_user_proto", "bpf_probe_read_user_proto", "bpf_probe_read_kernel_proto",
//			"bpf_probe_read_user_str_proto", "bpf_probe_read_kernel_str_proto", "bpf_probe_read_compat_proto", "bpf_probe_read_compat_str_proto",
//			"bpf_get_current_cgroup_id_proto", "bpf_get_current_ancestor_cgroup_id_proto", "bpf_send_signal_proto", "bpf_send_signal_thread_proto",
//			"bpf_perf_event_read_value_proto", "bpf_get_ns_current_pid_tgid_proto", "bpf_ringbuf_output_proto", "bpf_ringbuf_reserve_proto",
//			"bpf_ringbuf_submit_proto", "bpf_ringbuf_discard_proto", "bpf_ringbuf_query_proto", "bpf_jiffies64_proto",
//			"bpf_get_task_stack_proto", "bpf_copy_from_user_proto", "bpf_snprintf_btf_proto", "bpf_per_cpu_ptr_proto",
//			"bpf_this_cpu_ptr_proto", "bpf_task_storage_get_proto", "bpf_task_storage_delete_proto", "bpf_for_each_map_elem_proto",
//			"bpf_snprintf_proto", /*"bpf_get_func_ip_proto_tracing",*/ /*"bpf_spin_lock_proto", "bpf_spin_unlock_proto",*/
//			"bpf_timer_init_proto", "bpf_timer_set_callback_proto", "bpf_timer_start_proto", "bpf_timer_cancel_proto",
//	}},
//	"bpf_syscall": &BpfProgType{
//		Name: "bpf_syscall",
//		User: "void *",
//		Kern: "void *",
//		Enum: "BPF_PROG_SYSCALL",
//		SecDefs: []SecDef{
//			SecDef{"syscall/", nil}
//		},
//		FuncProtos: []string{//XXX: why missing this prog type
//	}},
}

type TracingIterCtx struct {
	Name string
	Ctx  *StructDef
}

/*
./kernel/bpf/map_iter.c:DEFINE_BPF_ITER_FUNC(bpf_map, struct bpf_iter_meta *meta, struct bpf_map *map)
./kernel/bpf/map_iter.c:DEFINE_BPF_ITER_FUNC(bpf_map_elem, struct bpf_iter_meta *meta,
./kernel/bpf/prog_iter.c:DEFINE_BPF_ITER_FUNC(bpf_prog, struct bpf_iter_meta *meta, struct bpf_prog *prog)
./kernel/bpf/task_iter.c:DEFINE_BPF_ITER_FUNC(task, struct bpf_iter_meta *meta, struct task_struct *task)
./kernel/bpf/task_iter.c:DEFINE_BPF_ITER_FUNC(task_file, struct bpf_iter_meta *meta,
./kernel/bpf/task_iter.c:DEFINE_BPF_ITER_FUNC(task_vma, struct bpf_iter_meta *meta,
./net/unix/af_unix.c:DEFINE_BPF_ITER_FUNC(unix, struct bpf_iter_meta *meta,
./net/ipv4/udp.c:DEFINE_BPF_ITER_FUNC(udp, struct bpf_iter_meta *meta,
./net/ipv4/tcp_ipv4.c:DEFINE_BPF_ITER_FUNC(tcp, struct bpf_iter_meta *meta,
./net/core/bpf_sk_storage.c:DEFINE_BPF_ITER_FUNC(bpf_sk_storage_map, struct bpf_iter_meta *meta,
./net/core/sock_map.c:DEFINE_BPF_ITER_FUNC(sockmap, struct bpf_iter_meta *meta,
./net/netlink/af_netlink.c:DEFINE_BPF_ITER_FUNC(netlink, struct bpf_iter_meta *meta, struct netlink_sock *sk)
./net/ipv6/route.c:DEFINE_BPF_ITER_FUNC(ipv6_route, struct bpf_iter_meta *meta, struct fib6_info *rt)
*/
var tracingIterCtxs = []TracingIterCtx{
	TracingIterCtx{Name:"bpf_map", Ctx: nil},
	TracingIterCtx{Name:"bpf_map_elem", Ctx: nil},
	TracingIterCtx{Name:"bpf_prog", Ctx: nil},
	TracingIterCtx{Name:"task", Ctx: nil},
	TracingIterCtx{Name:"task_file", Ctx: nil},
	TracingIterCtx{Name:"task_vma", Ctx: nil},
	TracingIterCtx{Name:"unix", Ctx: nil},
	TracingIterCtx{Name:"udp", Ctx: nil},
	TracingIterCtx{Name:"tcp", Ctx: nil},
	TracingIterCtx{Name:"bpf_sk_storage_map", Ctx: nil},
	TracingIterCtx{Name:"sockmap", Ctx: nil},
	TracingIterCtx{Name:"netlink", Ctx: nil},
	TracingIterCtx{Name:"ipv6_route", Ctx: nil},
}

func GenXdpEntry(r *randGen) (string, *StructDef) {
	return "", nil
}

func GenKprobeEntry(r *randGen) (string, *StructDef) {
	return "__x64_sys_nanosleep", nil
}

func GenTracepointEntry(r *randGen) (string, *StructDef) {
	return "sched/sched_switch", nil
}

func GenRawTracepointEntry(r *randGen) (string, *StructDef) {
	return "sys_enter", nil
}

func GenBPFTrampoline(r *randGen) (string, *StructDef) {
	return "__x64_sys_getpgid", nil
}

func GenTracingIter(r *randGen) (string, *StructDef) {
	i := r.Intn(len(tracingIterCtxs))
	return tracingIterCtxs[i].Name, nil
}

var CtxAccessMap = map[BpfProgTypeEnum]*BpfCtxAccess{
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCKET": [][]string{[]string{"offsetof", "struct bpf_sock_addr", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"user_ip4", "user_ip4"}, canRead: true, defaultSize: 4, narrowAccess: true, attachTypes: []string{
				"BPF_CGROUP_INET4_BIND", "BPF_CGROUP_INET4_CONNECT", "BPF_CGROUP_INET4_GETPEERNAME", "BPF_CGROUP_INET4_GETSOCKNAME", "BPF_CGROUP_UDP4_SENDMSG", "BPF_CGROUP_UDP4_RECVMSG"},},
			{rangeInCtx: []string{"user_ip6[0]", "user_ip6[3]"}, canRead: true, defaultSize: 4, wideAccess: true, narrowAccess: true, attachTypes: []string{
				"BPF_CGROUP_INET6_BIND", "BPF_CGROUP_INET6_CONNECT", "BPF_CGROUP_INET6_GETPEERNAME", "BPF_CGROUP_INET6_GETSOCKNAME", "BPF_CGROUP_UDP6_SENDMSG", "BPF_CGROUP_UDP6_RECVMSG"},},
			{rangeInCtx: []string{"msg_src_ip4", "msg_src_ip4"}, canRead: true, defaultSize: 4, narrowAccess: true, attachTypes: []string{
				"BPF_CGROUP_UDP4_SENDMSG"},},
			{rangeInCtx: []string{"msg_src_ip6[0]", "msg_src_ip6[3]"}, canRead: true, defaultSize: 4, wideAccess: true, narrowAccess: true, attachTypes: []string{
				"BPF_CGROUP_UDP6_SENDMSG"},},
			{rangeInCtx: []string{"user_ip4", "user_ip4"}, canWrite: true, size: 4, attachTypes: []string{
				"BPF_CGROUP_INET4_BIND", "BPF_CGROUP_INET4_CONNECT", "BPF_CGROUP_INET4_GETPEERNAME", "BPF_CGROUP_INET4_GETSOCKNAME", "BPF_CGROUP_UDP4_SENDMSG", "BPF_CGROUP_UDP4_RECVMSG"},},
			{rangeInCtx: []string{"user_ip6[0]", "user_ip6[3]"}, canWrite: true, size: 4, defaultSize: 4, wideAccess: true, attachTypes: []string{
				"BPF_CGROUP_INET6_BIND", "BPF_CGROUP_INET6_CONNECT", "BPF_CGROUP_INET6_GETPEERNAME", "BPF_CGROUP_INET6_GETSOCKNAME", "BPF_CGROUP_UDP6_SENDMSG", "BPF_CGROUP_UDP6_RECVMSG"},},
			{rangeInCtx: []string{"msg_src_ip4", "msg_src_ip4"}, canWrite: true, size: 4, attachTypes: []string{
				"BPF_CGROUP_UDP4_SENDMSG"},},
			{rangeInCtx: []string{"msg_src_ip6[0]", "msg_src_ip6[3]"}, canWrite: true, size: 4, defaultSize: 4, wideAccess: true, attachTypes: []string{
				"BPF_CGROUP_UDP6_SENDMSG"},},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSocketRegType{},},
			{rangeInCtx: []string{"default"}, canRead: true, size: 4,},
		},
	},
	BPF_PROG_TYPE_SCHED_CLS: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_META":         [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_meta", ""}},
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"family", "local_port"},},
			{rangeInCtx: []string{"mark", "mark"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"mark", "mark"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"tc_index", "tc_index"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"tc_index", "tc_index"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"priority", "priority"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"priority", "priority"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"tc_classid", "tc_classid"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"tc_classid", "tc_classid"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"queue_mapping", "queue_mapping"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"queue_mapping", "queue_mapping"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketMetaRegType{},},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true},
		},
	},
	BPF_PROG_TYPE_SCHED_ACT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_META":         [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_meta", ""}},
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"family", "local_port"},},
			{rangeInCtx: []string{"mark", "mark"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"mark", "mark"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"tc_index", "tc_index"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"tc_index", "tc_index"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"priority", "priority"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"priority", "priority"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"tc_classid", "tc_classid"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"tc_classid", "tc_classid"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"queue_mapping", "queue_mapping"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"queue_mapping", "queue_mapping"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketMetaRegType{},},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true},
		},
	},
	BPF_PROG_TYPE_LWT_OUT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"tc_classid"},},
			{rangeInCtx: []string{"family", "local_port"},},
			{rangeInCtx: []string{"data_meta"},},
			{rangeInCtx: []string{"tstamp"},},
			{rangeInCtx: []string{"wire_len"},},
			//
			{rangeInCtx: []string{"mark"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"priority"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			//bpf_skb_is_valid_access
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketRegType{}},
			{rangeInCtx: []string{"data_meta"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data_end"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketEndRegType{}},
			{rangeInCtx: []string{"flow_keys"},},
			{rangeInCtx: []string{"tstamp"}, canRead: true, canWrite: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true,},
		},
	},
	BPF_PROG_TYPE_LWT_XMIT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"tc_classid"},},
			{rangeInCtx: []string{"family", "local_port"},},
			{rangeInCtx: []string{"data_meta"},},
			{rangeInCtx: []string{"tstamp"},},
			{rangeInCtx: []string{"wire_len"},},
			//
			{rangeInCtx: []string{"mark"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"priority"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			//bpf_skb_is_valid_access
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketRegType{}},
			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketEndRegType{}},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true,},
		},
	},
	BPF_PROG_TYPE_PERF_EVENT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"sample_period", "sample_period"}, canRead: true, defaultSize: 8, narrowAccess: true,},
			{rangeInCtx: []string{"addr", "addr"}, canRead: true, defaultSize: 8, narrowAccess: true,},
			{rangeInCtx: []string{"default"}, canRead: true, size: 4,},
		},
	},
	BPF_PROG_TYPE_KPROBE: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"default"}, canRead: true,},
		},
	},
	BPF_PROG_TYPE_TRACEPOINT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"default"}, canRead: true,},
		},
	},
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"default"}, canRead: true,},
		},
	},
	BPF_PROG_TYPE_RAW_TRACEPOINT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"default"}, canRead: true,},
		},
	},
	BPF_PROG_TYPE_TRACING: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"default"}, canRead: true,}, //XXX btf_ctx_access
		},
	},
	BPF_PROG_TYPE_CGROUP_SYSCTL: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"write"}, canRead: true, defaultSize: 4, narrowAccess: true},
			{rangeInCtx: []string{"file_pos"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"file_pos"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"},},
		},
	},
	BPF_PROG_TYPE_XDP: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET":      [][]string{[]string{"offsetof", "struct xdp_md", "data", ""}},
			"PTR_TO_PACKET_META": [][]string{[]string{"offsetof", "struct xdp_md", "data_meta", ""}},
			"PTR_TO_PACKET_END":  [][]string{[]string{"offsetof", "struct xdp_md", "data_end", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"data"}, canRead: true, size: 4, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"data_meta"}, canRead: true, size: 4, regType: &PtrToPacketMetaRegType{},},
			{rangeInCtx: []string{"data_end"}, canRead: true, size: 4, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"rx_queue_index"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, size: 4,},
		},
	},
	BPF_PROG_TYPE_LIRC_MODE2: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"default"}, canRead: true, size: 4,},
		},
	},
	BPF_PROG_TYPE_SK_REUSEPORT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET_END":          [][]string{[]string{"offsetof", "struct sk_reuseport_md", "data_end", ""}},
			"PTR_TO_SOCKET":              [][]string{[]string{"offsetof", "struct sk_reuseport_md", "sk", ""}},
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct sk_reuseport_md", "migrating_sk", ""}},
			"PTR_TO_PACKET":              [][]string{[]string{"offsetof", "struct sk_reuseport_md", "data", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"data"}, canRead: true, size: 8, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"data_end"}, canRead: true, size: 8, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"hash"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"sk", "sk"}, canRead: true, size: 8, regType: &PtrToSocketRegType{},},
			{rangeInCtx: []string{"migrating_sk", "migrating_sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"eth_protocol", "eth_protocol"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"ip_protocol", "ip_protocol"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"bind_inany", "bind_inany"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"len", "len"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"default"},},
		},
	},
	BPF_PROG_TYPE_SOCK_OPS: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCKET_OR_NULL": [][]string{[]string{"offsetof", "struct bpf_sock_ops", "sk", ""}},
			"PTR_TO_PACKET":         [][]string{[]string{"offsetof", "struct bpf_sock_ops", "skb_data", ""}},
			"PTR_TO_PACKET_END":     [][]string{[]string{"offsetof", "struct bpf_sock_ops", "skb_data_end", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			//{rangeInCtx: []string{"reply"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"args[0]", "args[0]"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"sk_txhash"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"bytes_received", "bytes_acked"}, canRead: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSocketRegType{},},
			{rangeInCtx: []string{"skb_data"}, canRead: true, size: 8, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"skb_data_end"}, canRead: true, size: 8, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"default"}, canRead: true, size: 4,},
		},
	},
	BPF_PROG_TYPE_CGROUP_SKB: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"tc_classid"},},
			{rangeInCtx: []string{"data_meta"},},
			{rangeInCtx: []string{"wire_len"},},
//			{rangeInCtx: []string{"data"},},
//			{rangeInCtx: []string{"data_end"},},
			{rangeInCtx: []string{"mark"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"priority"}, canRead: true, canWrite: true,},
//			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
//			{rangeInCtx: []string{"tstamp"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketRegType{}},
			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketEndRegType{}},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true,},
//bpf_skb_is_valid_access
//			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
//			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
//			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
//			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
//			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true},
		},
	},
	BPF_PROG_TYPE_CGROUP_SOCK: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"state"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"family"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"type"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"protocol"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"dst_port"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"src_port"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"rx_queue_mapping"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"src_ip4", "src_ip4"}, canRead: true, defaultSize: 4, narrowAccess: true, attachTypes: []string{"BPF_CGROUP_INET4_POST_BIND"},},
			{rangeInCtx: []string{"src_ip6[0]", "src_ip6[3]"}, canRead: true, defaultSize: 4, narrowAccess: true, attachTypes: []string{"BPF_CGROUP_INET6_POST_BIND"},},
			{rangeInCtx: []string{"dst_ip4", "dst_ip4"}, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"dst_ip6[0]", "dst_ip6[3]"}, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"bound_dev_if"}, canRead: true, canWrite: true, defaultSize: 4, attachTypes: []string{"BPF_CGROUP_INET_SOCK_CREATE","BPF_CGROUP_INET_SOCK_RELEASE"},},
			{rangeInCtx: []string{"mark"}, canRead: true, canWrite: true, defaultSize: 4, attachTypes: []string{"BPF_CGROUP_INET_SOCK_CREATE","BPF_CGROUP_INET_SOCK_RELEASE"},},
			{rangeInCtx: []string{"priority"}, canRead: true, canWrite: true, defaultSize: 4, attachTypes: []string{"BPF_CGROUP_INET_SOCK_CREATE","BPF_CGROUP_INET_SOCK_RELEASE"},},
			{rangeInCtx: []string{"src_port"}, canRead: true, defaultSize: 4, attachTypes: []string{"BPF_CGROUP_INET4_POST_BIND","BPF_CGROUP_INET6_POST_BIND"},},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4,},
		},
	},
	BPF_PROG_TYPE_LWT_IN: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"tc_classid"},},
			{rangeInCtx: []string{"family", "local_port"},},
			{rangeInCtx: []string{"data_meta"},},
			{rangeInCtx: []string{"tstamp"},},
			{rangeInCtx: []string{"wire_len"},},
			//
			{rangeInCtx: []string{"mark"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"priority"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			//bpf_skb_is_valid_access
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketRegType{}},
			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketEndRegType{}},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true,},
//bpf_skb_is_valid_access
//			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
//			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data_meta"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data_end"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"flow_keys"},},
//			{rangeInCtx: []string{"tstamp"}, canRead: true, canWrite: true, size: 8,},
//			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
//			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true},
		},
	},
	BPF_PROG_TYPE_LWT_SEG6LOCAL: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"tc_classid"},},
			{rangeInCtx: []string{"family", "local_port"},},
			{rangeInCtx: []string{"data_meta"},},
			{rangeInCtx: []string{"tstamp"},},
			{rangeInCtx: []string{"wire_len"},},
			//
			{rangeInCtx: []string{"mark"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"priority"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			//bpf_skb_is_valid_access
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketRegType{}},
			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4,},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4, regType: &PtrToPacketEndRegType{}},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true,},
		},
	},
	BPF_PROG_TYPE_SK_SKB: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET":              [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_END":          [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"tc_classid", "tc_classid"},},
			{rangeInCtx: []string{"data_meta", "data_meta"},},
			{rangeInCtx: []string{"tstamp", "tstamp"},},
			{rangeInCtx: []string{"wire_len", "wire_len"},},
			{rangeInCtx: []string{"tc_index", "tc_index"}, canWrite: true,},
			{rangeInCtx: []string{"priority", "priority"}, canWrite: true,},
			{rangeInCtx: []string{"mark", "mark"},},
//			{rangeInCtx: []string{"data", "data"}, regType},
//			{rangeInCtx: []string{"data_end", "data_end"}, regType},
//bpf_skb_is_valid_access
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, /*canWrite: true,*/},
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, /*canWrite: true,*/ size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, /*canWrite: true,*/ size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, /*canWrite: true,*/ size: 4,},
			{rangeInCtx: []string{"data", "data"}, canRead: true, /*canWrite: true,*/ size: 4, regType: &PtrToPacketRegType{},},
//			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, /*canWrite: true,*/ size: 4,},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, /*canWrite: true,*/ size: 4, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, /*canWrite: true,*/ size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true},
		},
	},
	BPF_PROG_TYPE_SK_MSG: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET":     [][]string{[]string{"offsetof", "struct sk_msg_md", "data", ""}},
			"PTR_TO_PACKET_END": [][]string{[]string{"offsetof", "struct sk_msg_md", "data_end", ""}},
			"PTR_TO_SOCKET":     [][]string{[]string{"offsetof", "struct sk_msg_md", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"data", "data"}, canRead: true, size: 8, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, size: 8, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSocketRegType{},},
			{rangeInCtx: []string{"family", "family"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"local_ip4", "local_ip4"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"remote_port", "remote_port"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"local_port", "local_port"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"size", "size"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"default"},},
		},
	},
	BPF_PROG_TYPE_FLOW_DISSECTOR: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_PACKET":     [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data", ""}},
			"PTR_TO_PACKET_END": [][]string{[]string{"bpf_ctx_range", "struct __sk_buff", "data_end", ""}},
			"PTR_TO_FLOW_KEYS":  [][]string{[]string{"bpf_ctx_range_ptr", "struct __sk_buff", "flow_keys", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"data", "data"}, canRead: true, size: 4, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, size: 4, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"flow_keys", "flow_keys"}, canRead: true, size: 4, regType: &PtrToFlowKeysRegType{},},
			{rangeInCtx: []string{"default"},},
		},
	},
	BPF_PROG_TYPE_SOCKET_FILTER: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCK_COMMON_OR_NULL": [][]string{[]string{"offsetof", "struct __sk_buff", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"tc_classid", "tc_classid"},},
			{rangeInCtx: []string{"data", "data"},},
			{rangeInCtx: []string{"data_meta", "data_meta"},},
			{rangeInCtx: []string{"data_end", "data_end"},},
			{rangeInCtx: []string{"family", "local_port"},},
			{rangeInCtx: []string{"tstamp", "tstamp"},},
			{rangeInCtx: []string{"wire_len", "wire_len"},},
			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, size: 4,},
//			{rangeInCtx: []string{"data", "data"}, canRead: true, size: 4,},
//			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, size: 4,},
//			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, size: 4,},
			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
//			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, size: 8,},
			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true,},
//bpf_skb_is_valid_access
//			{rangeInCtx: []string{"cb[0]", "cb[4]"}, canRead: true, canWrite: true,},
//			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data", "data"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data_meta", "data_meta"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"data_end", "data_end"}, canRead: true, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"flow_keys", "flow_keys"},},
//			{rangeInCtx: []string{"tstamp", "tstamp"}, canRead: true, canWrite: true, size: 8,},
//			{rangeInCtx: []string{"sk"}, canRead: true, size: 8, regType: &PtrToSockCommonRegType{},},
//			{rangeInCtx: []string{"default"}, canWrite: true, size: 4,},
//			{rangeInCtx: []string{"default"}, canRead: true, defaultSize: 4, narrowAccess: true},
		},
	},
	BPF_PROG_TYPE_CGROUP_DEVICE: &BpfCtxAccess{
		regTypeMap: map[string][][]string{},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"access_type", "access_type"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"default"}, canRead: true, size: 4,},
		},
	},
	BPF_PROG_TYPE_CGROUP_SOCKOPT: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCKET":     [][]string{[]string{"offsetof", "struct bpf_sockopt", "sk", ""}},
			"PTR_TO_PACKET":     [][]string{[]string{"offsetof", "struct bpf_sockopt", "optval", ""}},
			"PTR_TO_PACKET_END": [][]string{[]string{"offsetof", "struct bpf_sockopt", "optval_end", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"retval"}, canWrite: true, size: 4, attachTypes: []string{"BPF_CGROUP_GETSOCKOPT"},},
			{rangeInCtx: []string{"optname"}, canWrite: true, size: 4, attachTypes: []string{"BPF_CGROUP_SETSOCKOPT"},},
			{rangeInCtx: []string{"level"}, canWrite: true, size: 4, attachTypes: []string{"BPF_CGROUP_SETSOCKOPT"},},
			{rangeInCtx: []string{"optlen"}, canWrite: true, size: 4,},
			{rangeInCtx: []string{"sk", "sk"}, canRead: true, size: 8, regType: &PtrToSocketRegType{},},
			{rangeInCtx: []string{"optval", "optval"}, canRead: true, size: 8, regType: &PtrToPacketRegType{},},
			{rangeInCtx: []string{"optval_end", "optval_end"}, canRead: true, size: 8, regType: &PtrToPacketEndRegType{},},
			{rangeInCtx: []string{"retval", "retval"}, canRead: true, size: 4, attachTypes: []string{"BPF_CGROUP_GETSOCKOPT"},},
			{rangeInCtx: []string{"default"}, canRead: true, size: 4,},
		},
	},
	BPF_PROG_TYPE_SK_LOOKUP: &BpfCtxAccess{
		regTypeMap: map[string][][]string{
			"PTR_TO_SOCKET_OR_NULL": [][]string{[]string{"offsetof", "struct bpf_sk_lookup", "sk", ""}},
		},
		others: map[string]*BpfCtxAccess{},
		accesses: []BpfCtxAccessAttr{
			{rangeInCtx: []string{"family", "family"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"protocol", "protocol"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"remote_ip4", "remote_ip4"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"local_ip4", "local_ip4"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"remote_ip6[0]", "remote_ip6[3]"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"local_ip6[0]", "local_ip6[3]"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"remote_port", "remote_port"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"local_port", "local_port"}, canRead: true, defaultSize: 4, narrowAccess: true,},
			{rangeInCtx: []string{"default"},},
		},
	},
}
