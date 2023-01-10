#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/page_counter.h>
#include <linux/kconfig.h>
#include <linux/types.h>

#define KB 1000
#define MB (1000*KB)

struct load_t
{
    u32 pid;
    u64 timestamp;

    u64 hwRSS;  //high water RSS
    u64 load_avg;   //cpu load avg

    u64 uid;    // user id
    u64 tgid;   // thread group id
    u64 real_parent;
    u64 parent;

    u32 on_cpu; // on which cpu threads this task runs-Kern

    u64 read;   // read data from disk in bytes

    u64 write;  // write data from disk in bytes

    char comm[16];  // process name
};


struct sched_process_exit
{
    char comm[16];
    u32 pid;
    u64 exit_time;
};


//logging stuff
BPF_PERF_OUTPUT(events);
//for proc exits
BPF_PERF_OUTPUT(exits);

/*
    Gather all performance data from task_struct from current monitored PID
*/
static void push_perf_data(struct bpf_perf_event_data *ctx)
{
    struct load_t curLoad = {0};

    curLoad.timestamp = bpf_ktime_get_ns();
    struct task_struct *task = NULL;

    task = (struct task_struct *)bpf_get_current_task();
    
    bpf_get_current_comm(curLoad.comm, sizeof(curLoad.comm));
    curLoad.uid = bpf_get_current_uid_gid();
    curLoad.pid = bpf_get_current_pid_tgid();
    curLoad.tgid = task->tgid;
    curLoad.real_parent = task->real_parent->pid;
    curLoad.parent = task->parent->pid;

    curLoad.on_cpu = bpf_get_smp_processor_id();
    curLoad.load_avg = task->se.avg.util_avg;

    curLoad.hwRSS = (task -> mm -> hiwater_rss) * PAGE_SIZE / (MB);

    curLoad.read = task->ioac.read_bytes ;
    curLoad.write = task->ioac.write_bytes ;

    events.perf_submit(ctx, &curLoad, sizeof(curLoad));

}

int trace_perf(struct bpf_perf_event_data *ctx)
{
    push_perf_data(ctx);
    return 0;
}

/*
    Tracepoint from /sys/kernel/debug/tracing/events/sched/sched_process_exit
    Becomes active when a process exits
*/
TRACEPOINT_PROBE(sched, sched_process_exit) 
{

    struct sched_process_exit proc_exit = {0};
    struct task_struct *task= NULL;
    task = (struct task_struct *)bpf_get_current_task();

    proc_exit.exit_time = bpf_ktime_get_ns();
    proc_exit.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(proc_exit.comm, sizeof(proc_exit.comm));

    exits.perf_submit(args, &proc_exit, sizeof(proc_exit));

    struct load_t curLoad = {0};

    curLoad.timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(curLoad.comm, sizeof(curLoad.comm));
    curLoad.uid = bpf_get_current_uid_gid();
    curLoad.pid = bpf_get_current_pid_tgid();
    curLoad.tgid = task->tgid;
    curLoad.real_parent = task->real_parent->pid;
    curLoad.parent = task->parent->pid;

    curLoad.on_cpu = bpf_get_smp_processor_id();
    curLoad.load_avg = task->se.avg.util_avg;

    curLoad.hwRSS = (task -> mm -> hiwater_rss) * PAGE_SIZE / (MB);

    curLoad.read = task->ioac.read_bytes ;
    curLoad.write = task->ioac.write_bytes ;

    events.perf_submit(args, &curLoad, sizeof(curLoad));
    return 0;
}

/*
    Tracepoint from /sys/kernel/debug/tracing/events/sched/sched_process_exec
    Becomes active when a process starts, usefull for short lived processes
*/
TRACEPOINT_PROBE(sched, sched_process_exec)
{
    struct load_t curLoad = {0};

    curLoad.timestamp = bpf_ktime_get_ns();
    struct task_struct *task = NULL;

    task = (struct task_struct *)bpf_get_current_task();

    bpf_get_current_comm(curLoad.comm, sizeof(curLoad.comm));
    curLoad.uid = bpf_get_current_uid_gid();
    curLoad.pid = bpf_get_current_pid_tgid();
    curLoad.tgid = task->tgid;
    curLoad.real_parent = task->real_parent->pid;
    curLoad.parent = task->parent->pid;

    curLoad.on_cpu = bpf_get_smp_processor_id();
    curLoad.load_avg = task->se.avg.util_avg;

    curLoad.hwRSS = (task -> mm -> hiwater_rss) * PAGE_SIZE / (MB);

    curLoad.read = task->ioac.read_bytes ;
    curLoad.write = task->ioac.write_bytes ;

    events.perf_submit(args, &curLoad, sizeof(curLoad));
    return 0;
}