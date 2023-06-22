import psutil
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

last_processes = [] # 存储上一次循环时的进程列表
cpu_count = 0 # 计数器，用于计算CPU利用率超过95%的次数
memory_count = 0 # 计数器，用于计算内存利用率超过95%的次数

def get_process_path(pid):
    try:
        process = psutil.Process(pid)
        path = process.exe()
        return path
    except:
        return None

def print_highest_usage(processes):
    highest_cpu = processes[0]
    highest_memory = processes[0]
    for proc in processes:
        if proc['cpu_percent'] > highest_cpu['cpu_percent']:
            highest_cpu = proc
        if proc['memory_percent'] > highest_memory['memory_percent']:
            highest_memory = proc

    cpu_path = get_process_path(highest_cpu['pid'])
    memory_path = get_process_path(highest_memory['pid'])

    if cpu_path is not None:
        print("CPU利用率最高的进程：")
        print(cpu_path)

    if memory_path is not None:
        print("内存利用率最高的进程：")
        print(memory_path)

while True:
    pids = psutil.pids() # 获取当前所有进程的PID列表
    time.sleep(0.1) # 等待一段时间，以便获取新进程
    new_pids = psutil.pids() # 获取当前所有进程的PID列表
    new_processes = set(new_pids) - set(pids) # 获取新进程的PID列表
    new_processes = list(new_processes)
    new_processes_info = []
    for pid in new_processes:
        try:
            process = psutil.Process(pid)
            path = os.path.abspath(process.exe())
            new_processes_info.append(path)
        except:
            pass
    if last_processes != new_processes_info: # 如果新进程与上一次循环时的进程不同，则输出新进程信息
        last_processes = new_processes_info
        for path in last_processes:
            print(path)
            print()

    cpu_percent = psutil.cpu_percent() # 获取CPU利用率
    memory_percent = psutil.virtual_memory().percent # 获取内存利用率

    if cpu_percent >= 95: # 如果CPU利用率超过95%
        cpu_count += 1 # 计数器加1
    else:
        cpu_count = 0

    if memory_percent >= 95: # 如果内存利用率超过95%
        memory_count += 1 # 计数器加1
    else:
        memory_count = 0

    if cpu_count >= 60 or memory_count >= 60: # 如果CPU或内存利用率超过95%的次数达到60次，则输出指定硬件占用率最高的进程的具体位置。
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            processes.append(proc.info)
        sorted_by_cpu = sorted(processes, key=lambda proc: proc['cpu_percent'], reverse=True)
        sorted_by_memory = sorted(processes, key=lambda proc: proc['memory_percent'], reverse=True)

        if cpu_count >= 60 and memory_count < 60:
            print_highest_usage(sorted_by_cpu)

        elif memory_count >= 60 and cpu_count < 60:
            print_highest_usage(sorted_by_memory)

        else:
            print_highest_usage(sorted_by_cpu)
            print_highest_usage(sorted_by_memory)

        cpu_count = 0
        memory_count = 0
import os
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 定义一个自定义的事件处理器
class MyEventHandler(FileSystemEventHandler):
    def __init__(self, path):
        super(MyEventHandler, self).__init__()
        self.path = os.path.abspath(path)

    def on_any_event(self, event):
        process_list = psutil.process_iter(['name', 'exe'])
        for process in process_list:
            try:
                if process.name() == "svchost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue  # 忽略C:\Windows\System32\svchost.exe进程
                if process.name() == "RuntimeBroker.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "winlogon.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "services.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "conhost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "dllhost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "SgrmBroker.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "ctfmon.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "sihost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "spoolsv.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "audiodg.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "dwm.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "lsass.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "csrss.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "wininit.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "smss.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "SearchIndexer.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "taskhostw.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "CompPkgSrv.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "fontdrvhost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "ChsIME.exe" and process.exe().startswith("C:\\Windows\\System32\\InputMethod\\CHS"):
                    continue
                if process.name() == "consent.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "UserOOBEBroker.exe" and process.exe().startswith("C:\\Windows\\System32\\oobe"):
                    continue
                if process.name() == "MoUsoCoreWorker.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.exe().startswith("C:\\Windows\\System32\\WindowsPowerShell"):
                    continue
                if process.exe().startswith("C:\\Windows\\SystemApps\\Microsoft.Windows."):
                    continue
                if process.exe().startswith("C:\\Windows\\SystemApps\\MicrosoftWindows."):
                    continue
                if process.exe().startswith("C:\\Windows\\System32\\DriverStore\\FileRepository"):
                    continue
                if process.exe().startswith("C:\\Windows\\SystemApps\\ShellExperienceHost_"):
                    continue
                if process.name() == "explorer.exe" and process.exe().startswith("C:\\Windows"):
                    continue
                if process.name() == "cmd.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "SearchProtocolHost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "SearchFilterHost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.name() == "backgroundTaskHost.exe" and process.exe().startswith("C:\\Windows\\System32"):
                    continue
                if process.exe() and self.path in process.exe():
                    print("位置: %s" % process.exe())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass


if __name__ == "__main__":
    syspath = "C:\Windows"

    event_handler = MyEventHandler(syspath)
    observer = Observer()
    observer.schedule(event_handler, syspath, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(0)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
