// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: nanshuaibo811@163.com
//
// Kernel space BPF program used for monitoring data for KVM event.

#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/kvm_exits.h"
#include "../include/kvm_vcpu.h"
#include "../include/kvm_mmu.h"
#include "../include/kvm_pic.h"
#include "../include/kvm_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t vm_pid = -1;
static struct common_event *e;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("fentry/kvm_vcpu_halt")
int BPF_PROG(fentry_kvm_vcpu_halt, struct kvm_vcpu *vcpu) {
    return trace_kvm_vcpu_halt(vcpu, vm_pid);
}

SEC("tp/kvm/kvm_vcpu_wakeup")
int tp_vcpu_wakeup(struct vcpu_wakeup *ctx) {
    return trace_kvm_vcpu_wakeup(ctx, &rb, e, vm_pid);
}

SEC("tp/kvm/kvm_halt_poll_ns")
int tp_kvm_halt_poll_ns(struct halt_poll_ns *ctx) {
    return trace_kvm_halt_poll_ns(ctx, &rb, e, vm_pid);
}

SEC("tp/kvm/kvm_exit")
int tp_exit(struct exit *ctx) {
    return trace_kvm_exit(ctx, vm_pid);
}

SEC("tp/kvm/kvm_entry")
int tp_entry(struct exit *ctx) {
    return trace_kvm_entry(&rb, e);
}

SEC("kprobe/mark_page_dirty_in_slot")
int BPF_KPROBE(kp_mark_page_dirty_in_slot, struct kvm *kvm,
               const struct kvm_memory_slot *memslot, gfn_t gfn) {
    return trace_mark_page_dirty_in_slot(kvm, memslot, gfn, &rb, e, vm_pid);
}

SEC("tp/kvm/kvm_page_fault")
int tp_page_fault(struct trace_event_raw_kvm_page_fault *ctx) {
    return trace_page_fault(ctx, vm_pid);
}

SEC("fexit/direct_page_fault")
int BPF_PROG(fexit_direct_page_fault, struct kvm_vcpu *vcpu,
             struct kvm_page_fault *fault) {
    return trace_direct_page_fault(vcpu, fault, &rb, e);
}

SEC("fentry/kvm_mmu_page_fault")
int BPF_PROG(fentry_kvm_mmu_page_fault, struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
             u64 error_code) {
    return trace_kvm_mmu_page_fault(vcpu, cr2_or_gpa, error_code, vm_pid);
}

SEC("fexit/handle_mmio_page_fault")
int BPF_PROG(fexit_handle_mmio_page_fault, struct kvm_vcpu *vcpu, u64 addr,
             bool direct) {
    return trace_handle_mmio_page_fault(vcpu, addr, direct, &rb, e);
}

SEC("fentry/kvm_pic_set_irq")
int BPF_PROG(fentry_kvm_pic_set_irq, struct kvm_pic *s, int irq,
             int irq_source_id, int level) {
    return trace_in_kvm_pic_set_irq(s, irq, irq_source_id, level, vm_pid);
}

SEC("fexit/kvm_pic_set_irq")
int BPF_PROG(fexit_kvm_pic_set_irq, struct kvm_pic *s, int irq,
             int irq_source_id, int level, int retval) {
    return trace_out_kvm_pic_set_irq(s, irq, irq_source_id, level, retval, &rb,
                                     e);
}