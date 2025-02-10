/*!
\brief Linux kernel IPC 观测工具
\TODO
    1. 将抓取到的数据，在终端输出
    2. 将抓取到的数据，存入pcap文件中，并可以使用wireshark进行分析
*/

// 使用fmt进行格式化输出
// 使用argparse库进行命令行解析

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

extern "C" {
#include <bpf/libbpf.h>
#include "ipc/ipcwatcher/ipcwatcher.skel.h"
}

#include "ipcwatcher.h"


// 事件处理回调
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct uds_event *e = reinterpret_cast<uds_event*>(data);
    const char *dir = e->direction == 0 ? "Send" : "Recv";
    printf("%s: PID=%lld Path=%s Len=%u\n", dir, e->pid, e->path, e->len);
}

int main() {
    struct ipcwatcher_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    // 1. 加载并验证BPF程序
    skel = ipcwatcher_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 2. 附加kprobe
    err = ipcwatcher_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    // 3. 设置Perf Buffer
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Tracing UDS send/recv events... Ctrl+C to exit.\n");

    // 4. 轮询事件
    while (true) {
        err = perf_buffer__poll(pb, 100 /* timeout_ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    ipcwatcher_bpf__destroy(skel);
    return err;
}
