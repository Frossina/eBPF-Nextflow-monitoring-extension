import multiprocessing
import statistics

import matplotlib.pylab as plt
import psutil

debug = False
child_pids = []
treeScannerStop = False

zippedMlog = list()
killed_procs = dict()
timeStamps = list()
loadGraph = list()
vmemGraph = list()
readGraph = list()
writeGraph = list()


def tree(pid):
    global treeScannerStop
    global child_pids
    cnt = 0
    while (not treeScannerStop):
        pids = []
        try:
            parent = psutil.Process(pid).parent()
        except psutil.NoSuchProcess:
            return
        child = parent.children(recursive=True)
        for proc in child:
            pids.append(proc.pid)

        child_pids = [str(num) for num in pids]
        child_pids.append(str(pid))
        cnt += 1
        if debug and (cnt % 250 == 0):
            print(child_pids)


def loadNsort(monPath, killPath):
    """
    @monPath: path to monitor file
    @killPath: path to killed proc file

    This functions sorts the data from file, ebpf does not log in correct time order
    """
    global zippedMlog, kill_dict
    timestampList = list()
    mPidList = list()
    loadList = list()
    onCoreList = list()
    rcharList = list()
    wcharList = list()
    vmList = list()
    threadList = list()

    with open(monPath) as mlog:
        for line in mlog:
            lineSplit = line.split(", ")
            timestampList.append(float(lineSplit[0]))
            loadList.append(float(lineSplit[1]))
            mPidList.append(int(lineSplit[2]))
            onCoreList.append(int(lineSplit[3]))
            rcharList.append(float(lineSplit[4]))
            wcharList.append(float(lineSplit[5]))
            threadList.append(int(lineSplit[7]))
            vmList.append(float(lineSplit[8]))

        mlog.close()
    with open(killPath) as kLog:
        for line in kLog:
            lineSplit = line.split(", ")
            killed_procs[int(lineSplit[1])] = float(lineSplit[0])
        kLog.close()
    zippedMlog = sorted(zip(timestampList, loadList, mPidList,
                            onCoreList, rcharList, wcharList, threadList, vmList))


def dataHandler(intervall, monPath, killPath):
    """
    @intervall: values in sec
    @monPath: path to monitor file
    @killPath: path to killed proc file

    Determines the active set of running prcosses in given intervall

    Saves the cpu usage, high water memory load, read, write 
    
    converts data to a graph
    """

    global killed_procs, timeStamps, loadGraph, vmemGraph, readGraph, writeGraph
    toUpdate = dict()

    active_procs = dict()  # active processes
    active_mem = dict()  # active ressources by thread, important for vm
    pid_lookup = dict()  # used by memory calculation
    active_cores = dict()  # load by core
    active_io = dict()  # io by pid

    start_ts = 0
    ts_counter = 0
    totalRead = 0
    prevRead = 0

    totalWrite = 0
    prevWrite = 0
    loadNsort(monPath, killPath)

    for mts, load, mpid, core, read, write, tgid, vm in zippedMlog:
        # set rel. time
        if start_ts == 0:
            start_ts = mts

        delta = mts - start_ts
        rel_timeStamp = mts - start_ts

        if tgid not in pid_lookup.keys():
            pid_lookup[tgid] = {mpid}
        else:
            pids = pid_lookup[tgid]
            pids.add(mpid)
            pid_lookup[tgid] = pids
        # active on core n
        if delta < intervall:

            # cpu graph
            if core not in active_cores.keys():
                active_cores[core] = [load]
            else:
                newCoreStat = active_cores[core]
                newCoreStat.append(load)
                active_cores[core] = newCoreStat

            # mem graph
            if tgid not in active_mem.keys():
                active_mem[tgid] = [vm]
            else:
                vmem = active_mem[tgid]
                vmem.append(vm)
                active_mem[tgid] = vmem

            if not isActive(mpid, mts):
                if mpid in active_mem.keys():
                    active_mem.pop(mpid)

            # read/write graph
            if mpid not in active_io.keys():
                active_io[mpid] = [read, write]
            else:
                active_io[mpid] = [read, write]

        else:
            start_ts = mts

            # calculate cpu load
            maxRow = 0
            loadSum = 0.0
            for cpu in active_cores.values():
                if len(cpu) > maxRow:
                    maxRow = len(cpu)
                loadSum += sum(cpu)

            timeStamps.append(ts_counter * intervall)

            if loadSum > 0:
                loadGraph.append(loadSum / maxRow / multiprocessing.cpu_count() * 100)
            else:
                loadGraph.append(0)

            memLoad = 0.0

            # calculate mem load
            for mem in active_mem.values():
                memLoad += statistics.median(mem)

            vmemGraph.append(memLoad)

            # check for killed prcoesses
            for tgid_key in pid_lookup.keys():
                pids = pid_lookup[tgid_key]
                dead = set()
                for pid in pids:
                    if not isActive(pid, mts):
                        dead.add(pid)
                # if tgid is dead remove from memory
                pids -= dead
                if len(pids) == 0:
                    if tgid_key in active_mem.keys():
                        active_mem.pop(tgid_key)
            # freeMem(pid_lookup, active_mem, mts)

            # calculate io rate
            totalWrite = 0
            totalRead = 0
            for read, write in active_io.values():
                totalWrite += write
                totalRead += read
            writeGraph.append((totalWrite - prevWrite) / intervall)
            readGraph.append((totalRead - prevRead) / intervall)

            prevWrite = totalWrite
            prevRead = totalRead

            # clean up
            active_cores.clear()
            # active_mem.clear()
            ts_counter += 1

    # plot cpu
    plt.plot(timeStamps, loadGraph, linewidth=1)
    plt.xlabel("Zeit in s")
    plt.ylabel("Auslastung in %")
    plt.savefig("cpu.svg")
    plt.clf()

    # plot mem
    plt.plot(timeStamps, vmemGraph, linewidth=1)
    plt.xlabel("Zeit in s")
    plt.ylabel("peak RSS in Mb")
    plt.savefig("mem.svg")
    plt.clf()

    # plot io graph
    fig, ax = plt.subplots()
    ax.plot(timeStamps, writeGraph, color="red", linewidth=1)
    ax.set_xlabel("Zeit in s")
    ax.set_ylabel("schreiben in Mb", color="red")

    ax2 = ax.twinx()
    ax2.plot(timeStamps, readGraph, color="blue", linewidth=1)
    ax2.set_xlabel("Zeit in s")
    ax2.set_ylabel("lesen in Mb", color="blue")

    fig.savefig("io.svg")
    fig.clf()


def isActive(pid, ts):
    global killed_procs
    kts = killed_procs.get(pid)
    if kts is not None:
        if ts < kts:
            return True
    else:
        return False


def containsID(id, active_procs):
    if id in active_procs.keys():
        return True
    return False


def freeMem(pid_lookup: dict, active_mem: dict, ts: float):
    for tgid in pid_lookup.keys():
        pids = pid_lookup[tgid]
        for pid in pids:
            if not isActive(pid, ts):
                pids.remove(pid)
    if len(pids) == 0:
        active_mem.pop(tgid)


def print_debug():
    global zippedMlog, killed_procs
    print(len(zippedMlog))
    print(len(killed_procs))



#File headers
line_headIO = ("%-11s %-14s %-6s %-1s %-7s\n" %
               ("TIME(ms),", "COMM,", "PID,", "T,", "kBYTES"))

line_headMem = ("TIME(ms), RSS in Mb, PID\n")

line_headCPU = ("TIME(ms), TOTAL CPU LOAD, PID %\n")
