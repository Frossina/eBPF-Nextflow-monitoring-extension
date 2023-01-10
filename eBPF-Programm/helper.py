import multiprocessing
import os
import statistics

import matplotlib.pylab as plt
from matplotlib.pyplot import cm
import matplotlib.dates as mdates
import numpy as np
from itertools import repeat
import mplcursors
import scipy.spatial as spatial

debug = False
child_pids = []

zippedMlog = list()
killed_procs = dict()
timeStamps = list()
loadGraph = list()
vmemGraph = list()
readGraph = list()
writeGraph = list()
taskLogList = list()

taskTimeOffset = 0


class Cursor:
    """
    A cross hair cursor.
    """

    def __init__(self, ax):
        self.ax = ax
        self.horizontal_line = ax.axhline(color='k', lw=0.8, ls='--')
        self.vertical_line = ax.axvline(color='k', lw=0.8, ls='--')
        # text location in axes coordinates
        self.text = ax.text(0.72, 0.9, '', transform=ax.transAxes)

    def set_cross_hair_visible(self, visible):
        need_redraw = self.horizontal_line.get_visible() != visible
        self.horizontal_line.set_visible(visible)
        self.vertical_line.set_visible(visible)
        self.text.set_visible(visible)
        return need_redraw

    def on_mouse_move(self, event):
        if not event.inaxes:
            need_redraw = self.set_cross_hair_visible(False)
            if need_redraw:
                self.ax.figure.canvas.draw()
        else:
            self.set_cross_hair_visible(True)
            x, y = event.xdata, event.ydata
            # update the line positions
            self.horizontal_line.set_ydata(y)
            self.vertical_line.set_xdata(x)
            self.text.set_text('x=%1.2f, y=%1.2f' % (x, y))
            self.ax.figure.canvas.draw()


def fmt(x, y):
    return 'x: {x:0.2f}\ny: {y:0.2f}'.format(x=x, y=y)


class FollowDotCursor(object):
    """Display the x,y location of the nearest data point.
    https://stackoverflow.com/a/4674445/190597 (Joe Kington)
    https://stackoverflow.com/a/20637433/190597 (unutbu)
    https://stackoverflow.com/questions/21583965/matplotlib-cursor-value-with-two-axes
    """

    def __init__(self, ax, x, y, formatter=fmt, offsets=(-20, 20)):
        try:
            x = np.asarray(x, dtype='float')
        except (TypeError, ValueError):
            x = np.asarray(mdates.date2num(x), dtype='float')
        y = np.asarray(y, dtype='float')
        mask = ~(np.isnan(x) | np.isnan(y))
        x = x[mask]
        y = y[mask]
        self._points = np.column_stack((x, y))
        self.offsets = offsets
        y = y[np.abs(y - y.mean()) <= 3 * y.std()]
        self.scale = x.ptp()
        self.scale = y.ptp() / self.scale if self.scale else 1
        self.tree = spatial.cKDTree(self.scaled(self._points))
        self.formatter = formatter
        self.ax = ax
        self.fig = ax.figure
        self.ax.xaxis.set_label_position('top')
        self.dot = ax.scatter(
            [x.min()], [y.min()], s=130, color='green', alpha=0.7)
        self.annotation = self.setup_annotation()
        plt.connect('motion_notify_event', self)

    def scaled(self, points):
        points = np.asarray(points)
        return points * (self.scale, 1)

    def __call__(self, event):
        ax = self.ax
        # event.inaxes is always the current axis. If you use twinx, ax could be
        # a different axis.
        if event.inaxes == ax:
            x, y = event.xdata, event.ydata
        elif event.inaxes is None:
            return
        else:
            inv = ax.transData.inverted()
            x, y = inv.transform([(event.x, event.y)]).ravel()
        annotation = self.annotation
        x, y = self.snap(x, y)
        annotation.xy = x, y
        annotation.set_text(self.formatter(x, y))
        self.dot.set_offsets((x, y))
        event.canvas.draw()

    def setup_annotation(self):
        """Draw and hide the annotation box."""
        annotation = self.ax.annotate(
            '', xy=(0, 0), ha='right',
            xytext=self.offsets, textcoords='offset points', va='bottom',
            bbox=dict(
                boxstyle='round,pad=0.5', fc='yellow', alpha=0.75),
            arrowprops=dict(
                arrowstyle='->', connectionstyle='arc3,rad=0'))
        return annotation

    def snap(self, x, y):
        """Return the value in self.tree closest to x, y."""
        dist, idx = self.tree.query(self.scaled((x, y)), k=1, p=1)
        try:
            return self._points[idx]
        except IndexError:
            # IndexError: index out of bounds
            return self._points[0]


def loadNsort(monPath, killPath):
    """
    @monPath: path to monitor file
    @killPath: path to killed proc file

    This functions sorts the data from file, ebpf does not log in correct time order
    """
    global zippedMlog, taskLogList, kill_dict
    timestampList = list()
    mPidList = list()
    loadList = list()
    onCoreList = list()
    rcharList = list()
    wcharList = list()
    vmList = list()
    threadList = list()
    taskLogList = list()
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


def dataHandler(intervall, monPath, killPath, timeNow):
    """
    @intervall: values in sec
    @monPath: path to monitor file
    @killPath: path to killed proc file

    Determines the active set of running prcosses in given intervall

    Saves the cpu usage, high water memory load, read, write 
    
    converts data to a graph
    """

    global killed_procs, timeStamps, loadGraph, vmemGraph, readGraph, writeGraph, taskTimeOffset
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
    abs_start = 0
    totalWrite = 0
    prevWrite = 0
    loadNsort(monPath, killPath)
    lastTS = 0
    for mts, load, mpid, core, read, write, tgid, vm in zippedMlog:
        # set rel. time
        if start_ts == 0:
            start_ts = mts
            abs_start = mts

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
            lastTS = ts_counter * intervall
    tasks = getTaskBars(timeNow, lastTS)
    print(len(loadGraph))
    # plot cpu
    fig = plt.figure(figsize=(30, 50))
    ax1 = fig.add_subplot(111)
    ax2 = ax1.twinx()

    line = ax1.plot(timeStamps, loadGraph, linewidth=1)
    ax1.set_xlabel("Zeit in s")
    ax1.set_ylabel("Auslastung in %")

    taskName, taskStart, taskEnd = list(zip(*tasks))
    color = iter(cm.rainbow(np.linspace(0, 1, len(taskName))))
    minimum = 0
    maximum = 100
    # y = list()
    for i in range(len(taskName)):
        duration = (taskEnd[i] - taskStart[i])  # convert to sec
        xmin = taskStart[i] + (((len(loadGraph))*intervall - max(taskStart))/len(taskName))
        xmax = (taskStart[i] + duration) +(((len(loadGraph))*intervall - max(taskStart))/len(taskName))

        # ax.text(xmin + 0.1, (2*(i+1))+0.15, taskName[i], fontsize=8)
        c = next(color)
        # ax2.hlines(y=(3) * ((-1) ** i), xmin=xmin, xmax=xmax, lw=2, label=taskName[i], color=c)
        ax2.hlines(y=0.5 * (i + 1), xmin=xmin, xmax=xmax, lw=2, label=taskName[i], color=c)
        # y.extend(repeat((2 * (i + 1)),int((xmax-xmin)/intervall)))
    ax2.legend(bbox_to_anchor=(1, 1), loc='upper left', prop={'size': 6})
    ax2.get_yaxis().set_visible(False)
    ax2.set_ylim([-1, (len(taskName) + 1) * 1])
    ax1.set_ylim([-1, 100])
    c1 = FollowDotCursor(ax1, timeStamps, loadGraph)
    mplcursors.cursor(multiple=True)
    fig.savefig("cpu.svg", bbox_inches='tight')

    # plot mem
    fig = plt.figure(figsize=(30, 50))
    ax1 = fig.add_subplot(111)
    ax2 = ax1.twinx()

    ax1.plot(timeStamps, vmemGraph, linewidth=1)
    ax1.set_xlabel("Zeit in s")
    ax1.set_ylabel("peak RSS in Mb")
    color = iter(cm.rainbow(np.linspace(0, 1, len(taskName))))
    for i in range(len(taskName)):
        duration = (taskEnd[i] - taskStart[i])  # convert to sec
        xmin = taskStart[i] + (((len(loadGraph))*intervall - max(taskStart))/len(taskName))
        xmax = (taskStart[i] + duration) +(((len(loadGraph))*intervall - max(taskStart))/len(taskName))

        # ax.text(xmin + 0.1, (2*(i+1))+0.15, taskName[i], fontsize=8)
        c = next(color)
        ax2.hlines(y=0.5 * (i + 1), xmin=xmin, xmax=xmax, lw=2, label=taskName[i], color=c)
    ax2.legend(bbox_to_anchor=(1, 1), loc='upper left', prop={'size': 6})
    ax2.get_yaxis().set_visible(False)
    ax2.set_ylim([0, (len(taskName) + 1) * 1])
    ax1.set_ylim([0, max(vmemGraph) + 100])
    fig.savefig("mem.svg", bbox_inches='tight')
    c1 = FollowDotCursor(ax1, timeStamps, vmemGraph)
    mplcursors.cursor(multiple=True)

    # plot io graph write
    fig = plt.figure(figsize=(30, 50))
    ax1 = fig.add_subplot(111)
    ax2 = ax1.twinx()

    ax1.plot(timeStamps, writeGraph, linewidth=1)
    ax1.set_xlabel("Zeit in s")
    ax1.set_ylabel("schreiben in Mb")
    color = iter(cm.rainbow(np.linspace(0, 1, len(taskName))))
    print(min(taskStart))
    print(max(taskStart))
    for i in range(len(taskName)):
        duration = (taskEnd[i] - taskStart[i])  # convert to sec
        xmin = taskStart[i] + (((len(loadGraph))*intervall - max(taskStart))/len(taskName))
        xmax = (taskStart[i] + duration) +(((len(loadGraph))*intervall - max(taskStart))/len(taskName))

        # ax.text(xmin + 0.1, (2*(i+1))+0.15, taskName[i], fontsize=8)
        c = next(color)
        ax2.hlines(y=0.5 * (i + 1), xmin=xmin, xmax=xmax, lw=2, label=taskName[i], color=c)
    ax2.legend(bbox_to_anchor=(1, 1), loc='upper left', prop={'size': 6})
    ax2.get_yaxis().set_visible(False)
    ax2.set_ylim([0, (len(taskName) + 1) * 1])
    ax1.set_ylim([0, max(writeGraph) + 100])
    fig.savefig("io_write.svg", bbox_inches='tight')
    c1 = FollowDotCursor(ax1, timeStamps, writeGraph)
    mplcursors.cursor(multiple=True)

    # plot io graph read
    fig = plt.figure(figsize=(30, 50))
    ax1 = fig.add_subplot(111)
    ax2 = ax1.twinx()

    ax1.plot(timeStamps, readGraph, linewidth=1)
    ax1.set_xlabel("Zeit in s")
    ax1.set_ylabel("lesen in Mb")
    color = iter(cm.rainbow(np.linspace(0, 1, len(taskName))))
    for i in range(len(taskName)):
        duration = (taskEnd[i] - taskStart[i])  # convert to sec
        xmin = taskStart[i] + (((len(loadGraph))*intervall - max(taskStart))/len(taskName))
        xmax = (taskStart[i] + duration) +(((len(loadGraph))*intervall - max(taskStart))/len(taskName))

        # ax.text(xmin + 0.1, (2*(i+1))+0.15, taskName[i], fontsize=8)
        c = next(color)
        ax2.hlines(y=0.5 * (i + 1), xmin=xmin, xmax=xmax, lw=2, label=taskName[i], color=c)
    ax2.legend(bbox_to_anchor=(1, 1), loc='upper left', prop={'size': 6})
    ax2.get_yaxis().set_visible(False)
    ax2.set_ylim([0, (len(taskName) + 1) * 1])
    ax1.set_ylim([0, max(readGraph) + max(readGraph) / 2])
    fig.savefig("io_read.svg", bbox_inches='tight')
    c1 = FollowDotCursor(ax1, timeStamps, readGraph)
    mplcursors.cursor(multiple=True)

    plt.show()


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


def getTaskBars(timeNow, lastTS):
    bootime = 0
    with open("/root/upt", "r") as upt:
        for line in upt:
            split = line.split(" ")
            bootime = float(split[0])
            # print(bootime)
    global taskLogList, taskTimeOffset
    taskList = list()

    with open('TaskLog') as TLog:
        next(TLog)
        next(TLog)
        n = 0;
        for line in TLog:
            if n == 0:
                lineSplit = line.split(", ")
                taskTimeOffset = int(lineSplit[1]) / 1000
                n += 1
            else:
                taskLogList.append(line)
    start = 0

    tasks = list()
    tasksStartList = list()
    tasksEnd = list()

    for line in taskLogList:
        lineSplit = line.split(", ")
        taskName = lineSplit[0]
        taskStart = int(lineSplit[1]) / 1000
        taskEnd = int(lineSplit[2]) / 1000
        taskDuration = int(lineSplit[3])
        if start == 0:
            start = taskStart

        tasks.append(taskName)

        taskStart -= start
        tasksStartList.append(taskStart)

        taskEnd -= start
        tasksEnd.append(taskEnd)
        taskTimeOffset = lastTS - (taskEnd) + 2
    print(timeNow)
    print(taskEnd)
    print(lastTS)
    print(taskTimeOffset)
    return list(zip(tasks, tasksStartList, tasksEnd))


# File headers
line_headIO = ("%-11s %-14s %-6s %-1s %-7s\n" %
               ("TIME(ms),", "COMM,", "PID,", "T,", "kBYTES"))

line_headMem = ("TIME(ms), RSS in Mb, PID\n")

line_headCPU = ("TIME(ms), TOTAL CPU LOAD, PID %\n")
