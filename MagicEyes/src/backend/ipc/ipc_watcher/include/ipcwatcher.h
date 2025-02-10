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

// ipcwatcher libbpf 内核<->用户 传递信息相关结构体

#ifndef IPC_IPC_WATCHER__IPC_WATCHER_H
#define IPC_IPC_WATCHER__IPC_WATCHER_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

/*
struct event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 saddr_len;
    struct sockaddr_un saddr;
    u32 daddr_len;
    struct sockaddr_un daddr;
    u32 len;
    u64 timestamp;
};
*/
// 定义事件数据结构
struct uds_event {
    u64 pid;
    char path[108];     // UNIX_PATH_MAX = 108
    u32 len;
    u8 direction;     // 0:发送, 1:接收
};

#endif /* IPC_IPC_WATCHER__IPC_WATCHER_H */
