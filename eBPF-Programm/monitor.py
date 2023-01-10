import argparse
import os
import time
from typing import List
from bcc import BPF, PerfType, PerfSWConfig, PerfHWConfig
import time
import helper
import psutil

sample_freq = 50
sample_res = 0.25  # in sec

toSec = 1000000000  # nsec to sec

ts_start = 0
start_ts = 0
counter = 0

buffer = list()

# nf logs
cmd_out = open("nf_log.txt", "w")
cmd_out.close()
# Monitor log
monitor_log_path = 'monitor_log.txt'
monitor_log = open(monitor_log_path, 'a')
monitor_log.close()

parser = argparse.ArgumentParser(description="Monitoring")
parser.add_argument("-p")
args = parser.parse_args()
pid = 0
if args.p:
    pid = args.p

bpf = BPF(src_file='monitor.c')

# periodic task stat
bpf.attach_perf_event(ev_type=PerfType.HARDWARE,
                      ev_config=PerfHWConfig.CPU_CYCLES,
                      fn_name="trace_perf",
                      sample_period=0,
                      sample_freq=sample_freq)


def writeBuffer(path):
    global buffer
    if len(buffer) > 0:
        with open(path, "a") as mlog:
            mlog.writelines(buffer)
            mlog.flush()
            os.fsync(mlog)
            mlog.close()


def print_event(cpu, data, size):
    global ts_start
    global counter
    global buffer
    cpu_event = bpf["events"].event(data)
    comm = cpu_event.comm.decode("utf-8")
    # crude pid filter
    if (cpu_event.pid != 0 and cpu_event.pid != os.getpid() and cpu_event.pid >= int(
            pid) and cpu_event.uid == 0) or ("docker" in comm) or ("containerd-shim" in comm):
        ts = cpu_event.timestamp / toSec  # time of sample
        lineLogCpu = (" %.6lf, %lf, %ld, %s" %
                      (ts, (cpu_event.load_avg / 1024), cpu_event.pid, cpu_event.on_cpu))
        lineLogDisk = (", %s, %s, %s, %s" %
                       (cpu_event.read / 1000000, cpu_event.write / 1000000, cpu_event.comm, cpu_event.tgid))
        lineLogMem = (", %s" %
                      cpu_event.hwRSS)

        linePID = (", %d, %d" % (cpu_event.real_parent, cpu_event.parent))

        line = lineLogCpu + lineLogDisk + lineLogMem + linePID + "\n"

        buffer.append(line)
        counter += 1
        if (counter % 5000) == 0:
            # print("writing buffer")
            writeBuffer(monitor_log_path)
            buffer.clear()
            counter = 0


def print_exits(cpu, data, size):
    global ts_start
    event = bpf["exits"].event(data)

    if event.pid != 0 and event.pid != os.getpid and event.pid >= int(pid):
        ev_time = event.exit_time / toSec
        ev_pid = event.pid
        ev_comm = event.comm
        fmt_line = ("%.4lf, %ld, %s\n" % (ev_time, ev_pid, ev_comm))
        kill_stat.write(fmt_line)
        kill_stat.flush()
        os.fsync(kill_stat)


# bcc execsnoop fix if kernel return 0 as ppid
def get_ppid(PID):
    ppid = 0
    """
    try:
        with open("/proc/%d/status" % PID) as status:
            for line in status:
                if line.startswith("PPid:"):
                    ppid = int(line.split()[1])
            with open("nf_log.txt", "a") as file:
                file.write("Process: %s found parent with ID: %s" % (pid, ppid))
                file.close()
    except IOError:
        pass
    """

    return 0


killed_proc_path = "killedProcs.txt"
kill_stat = open(killed_proc_path, "w")

bpf["events"].open_perf_buffer(print_event, page_cnt=4096)
bpf["exits"].open_perf_buffer(print_exits, page_cnt=4096)

print("Tracing PID: %s \n" % pid)

# creates file to signal nextflow to continue
ready = open("ready", "w")
timeNow = round(time.time() * 1000)
ready.close()

# starts the monitoring loop
while 1:
    try:
        if os.path.isfile("nf_done"):
            bpf.perf_buffer_poll()
            print("nf has finished... exit monitoring")
            break
        # time.sleep(1 / 10)
    except KeyboardInterrupt:
        print("Keyboard interrupt\n")
        break
    except OSError:
        break

kill_stat.close()

print("writing buffers\n")
# clean and write buffer
writeBuffer(monitor_log_path)
buffer.clear()

print("calculating graphs\n")
helper.dataHandler(sample_res, monPath=monitor_log_path, killPath=killed_proc_path, timeNow=timeNow)

print("all task done ... \n")
