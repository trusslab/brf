# BPF Runtime Fuzzer (BRF)
BRF is a coverage-guided fuzzer that aims to fuzz the runtime compononets of eBPF shielded by the verifier. BRF uses semantic-aware and dependency-aware input generation/mutation logic as well as generating syscalls to trigger the execution of eBPF programs to achieve the goal. The implementation of BRF is based on Syzkaller.

## Prerequisites

### LLVM
To use latest bpf features, it is better to build the kernel using the latest llvm.

``` bash
git clone --branch llvmorg-17.0.6 https://github.com/llvm/llvm-project.git
mkdir llvm-project/build; cd llvm-project/build
cmake ../llvm -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
	-DLLVM_ENABLE_PROJECTS=clang \
	-DBUILD_SHARED_LIBS=OFF \
	-DCMAKE_BUILD_TYPE=Release \
	-DLLVM_BUILD_RUNTIME=OFF
make
```
After the build completes, export build/bin to $PATH.

### Pahole
``` bash
git clone --branch v1.24 https://github.com/acmel/dwarves.git
mkdir dwarves/build; cd dwarves/build
cmake ../
make
sudo make install
```

More to be added. Let us know if you think something should be added here.

### Build Linux kernel
Here we use the development branch of network device subsystem of the Linux kernel.
``` bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git $KERNEL
cd $KERNEL
make CC=clang-17 defconfig
make CC=clang-17 kvm_guest.config
```
Follow the [guide](/docs/linux/kernel_configs.md) and enable kernel configs required by Syzkaller

Enable bpf-related configs by editing .config or through menuconfig.
``` make
CONFIG_BPF_SYSCALL
CONFIG_BPF_JIT
CONFIG_BPF_LSM
CONFIG_DEBUG_INFO_BTF
CONFIG_MODULE_ALLOW_BTF_MISMATCH
CONFIG_TEST_BPF
CONFIG_CGROUP_BPF
CONFIG_NET_ACT_BPF
CONFIG_NET_CLS_BPF
CONFIG_BPF_STREAM_PARSER
CONFIG_LWTUNNEL_BPF
CONFIG_IPV6_SEG6_BPF
CONFIG_LIRC
CONFIG_BPF_LIRC_MODE2
```

Finally, build the Linux kernel with Clang/LLVM.
``` make
make CC=clang-17
```

Build bpftool and libbpf to be used later
``` bash
cd $KERNEL/tools/bpf/bpftool
make CC=clang-17
cd $KERNEL/tools/lib/bpf
make
```

### Create Debian Bookworm Linux image
``` bash
mkdir $IMAGE; cd $IMAGE
cp $SYZKALLER/tools/create-image.sh .
chmod +x create-image.sh
ADD_PACKAGE="make,sysbench,git,vim,tmux,usbutils,tcpdump,clang-16" ./create-image.sh --feature full --distribution bookworm --seek 8191
```

### Prepare the image for compiling BPF programs
Prepare BRF working directory. The directory will be shared with the guest to store and compile BPF programs.
``` bash
mkdir $BRF_WORKDIR; cd $BRF_WORKDIR
cp $KERNEL/tools/bpf/bpftool/vmlinux.h .
```

Boot into the guest and install libbpf headers.
``` bash
qemu-system-x86_64 \
        -m 2G \
        -smp 2 \
        -kernel $KERNEL/arch/x86/boot/bzImage \
        -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
        -drive file=$IMAGE/bookworm.img,format=raw \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
        -net nic,model=e1000 \
	-virtfs local,path=$KERNEL,mount_tag=host0,security_model=mapped,id=host0 \
        -enable-kvm \
        -nographic \
        -pidfile vm.pid \
        2>&1 | tee vm.log
```
``` bash
mkdir /mnt/kernel_src
mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/kernel_src
cd /mnt/kernel_src/tools/lib/bpf
make install_headers
```
## Run BRF
Create a config like the following and replace $SYZKALLER, $KERNEL, $IMAGE and $BRF\_WORKDIR with the actual paths.
``` json
{
        "target": "linux/amd64",
        "http": "127.0.0.1:56741",
        "workdir": "$SYZKALLER/workdir/bookworm",
        "kernel_obj": "$KERNEL",
        "image": "$IMAGE/bookworm.img",
        "sshkey": "$IMAGE/bookworm.id_rsa",
        "syzkaller": "$SYZKALLER",
        "procs": 8,
        "type": "qemu",
        "vm": {
                "count": 4,
                "kernel": "$KERNEL/arch/x86/boot/bzImage",
                "cpu": 2,
                "mem": 2048,
		"brf_workdir": "$BRF_WORKDIR"
        }
}
```
Run Syzkaller manager:
```
mkdir -p workdir/bookworm
./bin/syzkaller -config my.cfg
```
## Acknoledgement
