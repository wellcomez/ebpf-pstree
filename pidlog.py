import os
import time
import psutil
def timestr():
    # import time
    import datetime
    s = datetime.datetime.now().strftime("%H:%M:%S.%f")
    # s = time.strftime("%H:%M:%S", time.localtime(st))
    return s
def join_byte_to_string(v):
    try:
        c = map(lambda x:x.decode('utf-8'),v)
        ret = " ".join(list(c))
        # print(a, ret)
        return ret
    except Exception as e:
        print(e)
        return None

def get_nspid_from_status(pid):
    name = "/proc/%d/status" % pid
    ret = ""
    try:
        ret = open(name).read()
    except Exception as e:
        return None
    sss = ret.split("\n")
    t = "NSpid:"
    for line in sss:
        try:
            line.index(t)
            nn = line[len(t):].split('\t')
            nn = list(filter(lambda x: len(x) > 0, nn))
            if len(nn) == 2:
                return int(nn[1])
        except:
            pass
    return None


def get_comm(pid):
    try:
        name = "/proc/%d/comm" % pid
        ret = open(name).read()
        ret = ret[0:-1]
        return ret
    except:
        return "????"


def get_exe(pid):
    name = "/proc/%d/exe" % pid
    try:
        return os.readlink(name)
    except:
        return "????"


def get_pid_namespace(pid):
    try:
        name = "/proc/%d/ns/pid" % pid
        return os.readlink(name)
    except:
        return "????"


def get_cmdline(pid):
    try:
        name = "/proc/%d/cmdline" % pid
        ret = open(name).read()
        ret = ret[0:-1]
        return ret
    except:
        return "????"


class ContainEvent(object):

    def __init__(self, event=None, cmdline=None):
        self.rootnode = False
        self.cmdline = ""
        self.parentname = ""
        self.syscall = -1
        self.comm = ""
        self.pid = None
        self.ppid = None
        self.uid = None
        self.ns_pid = None
        self.ns_process = ""
        if event != None:
            self.pid = event.pid
            self.ppid = event.ppid
            self.comm = event.comm.decode("utf-8")
            self.uid = event.uid
            self.get_parentname_proc()
            self.syscall = event.syscall
        if cmdline != None:
            self.cmdline = cmdline.decode('utf-8')
            cmd = self.cmdline.split(" ")[0]
            appfull = os.path.basename(cmd)
            if appfull.find(self.comm) == 0:
                self.comm = appfull
        self.st = time.time()
        self.time= timestr()
        self.child = []
        pass

    def get_comm_from_cmdline(self,cmdline):
        cmd = cmdline.split(" ")[0]
        appfull = os.path.basename(cmd)
        if appfull.find(self.comm) == 0:
            self.comm = appfull

    def isRootNode(self):
        return self.rootnode or self.ppid == None

    def get_parentname_proc(self):
        try:
            self.parentname = get_comm(self.ppid)
            self.ns_process = get_pid_namespace(self.pid)
            self.ns_pid = get_nspid_from_status(self.pid)
        except:
            pass

    def running(self):
        return os.path.exists("/proc/%d" % (self.pid))

    def __str__(self) -> str:
        if self.ns_pid is None:
            return "%d %s" % (self.pid, self.comm)
        else:
            child=""
            # (str(len(self.child))+"->" if len(self.child) else "")
            return "%d%s %d %s %s" % (self.ns_pid, 
                                            "*" if len(self.child) else "",
                                            self.pid, self.comm,child)

    def ischild(self, b):
        return self.pid == b.ppid

    def updatechild(self):
        for a in self.child:
            a.parentname = self.comm

    def addchild(self, a):
        self.child.append(a)
        if self.comm != None and len(self.comm):
            a.parentname = self.comm

    def find(self, a):
        if a.ppid == self.pid:
            return self
        for c in self.child:
            b = c.find(a)
            if b != None:
                return b
        return None
    def del_none(self,d):
        for key, value in list(d.items()):
            if value is None:
                del d[key]
        return d  
    def dict(self, ppid=False, cmdline=True):
        # child = list(map(lambda x: x.dict(
        #     ppid=ppid, cmdline=cmdline), self.child))
        child = {}
        for a in self.child:
            child[str(a)] = a.dict(ppid)
        run = self.running()
        ret = {
            "nspid":   str(self.ns_pid) if self.ns_pid!=None else None,
            "uid": self.uid if self.uid != None else "???",
            "ppid": self.ppid if self.ppid != None else "???",
            "app": self.comm if self.comm != None else "???",
            "cmdline" : self.cmdline if cmdline else "???",
            "st": self.st,
            "time": self.time,
            "status" : "closed" if run == False else "running"
        }
        if len(child):
            pid = self.ns_pid if self.ns_pid!=None else ""
            ret["%s %s child*%d -%-9d" % (pid,self.comm, len(child), self.pid)] = child
        run = self.running()

        ret["status"] = "closed" if run == False else "running"
        # else:
        #     ret["pid"] = self.pid
        return ret


class logger:

    def __init__(self, filename="pid", systemdwide=False) -> None:
        self.ppid = set()
        self.events = {}
        self.root = []
        self.filename = filename
        self.systemdwide = systemdwide
        self.filename = "ebpf-%s.log" % (filename)
        # fp = open(self.filename, "a")
        self.treename = "ebpf-%s.json" % (filename)
        self.logfile = None
        if self.systemdwide:
            self.add_current_process()
        pass

    def openfile(self,name):
        if name !=None:
            self.filename = "ebpf-%s.log" % (name)
            self.treename = "ebpf-%s.json" % (name)
        if self.logfile is None:
            fp = open(self.filename, "a")
            self.logfile = fp
            return fp
        else:
            return self.logfile

    def fixcmdline(self,args):
        if args is None:return
        for e in self.events.values():
            if args !=None:
                try:
                    l = args[e.pid]
                    cmd = join_byte_to_string(l)
                    if cmd!=e.cmdline:
                        print("\n----begin---------------",e.pid, e.comm,
                              "\ncmd",
                              "\n", cmd if cmd!=None and len(cmd)>1 else "empty",
                              "\nevent cmdline"
                              "\n",e.cmdline if len(e.cmdline) > 0 else "empty",
                              "\n--------------------------------------------"
                              )
                        if  cmd!=None:
                            e.get_comm_from_cmdline(cmd)
                            e.cmdline = cmd
                        print("\n final cmdline:"
                              "\n",str(e),
                              "\n--------------------------------------------")
                except:
                    pass
    def add_current_process(self):
        for event in psutil.process_iter(['pid', 'name', 'ppid']):
            a = ContainEvent()
            a.pid = event.pid
            a.ppid = event.ppid()
            a.get_parentname_proc()
            a.comm = event.name()
            uid = event.uids().real
            a.uid = uid
            # a.uid = event.uid
            self.add(a)
        # self.update_all_parent_name()
        pass

    def write2log(self, event:ContainEvent):
        s =event.time
        line = "%s %-4d %6s %6s %40s %6s %40s %-6d  %s %s\n" % (s, (event.st-int(event.st)+1)*100000,
                                                             str(event.ns_pid) if event.ns_pid != None else "",
                                                             str(
                                                                 event.pid) if event.pid != None else "", event.comm,
                                                             str(
                                                                 event.ppid) if event.ppid != None else "", event.parentname,
                                                             event.uid if event.uid != None else -1,  event.cmdline,
                                                             "fork="+str(event.ppid) if event.syscall == 2 else "")
        
        self.openfile(None).write(line)

    def add(self, event: ContainEvent):
        return self._add(event)

    def _add(self, event: ContainEvent):
        self.ppid.add(event.pid)
        if event.pid not in self.events:
            self.events[event.pid] = event
        elif event.syscall == 1:
            c = self.events[event.pid]
            event.child.extend(c.child)
            self.events[event.pid] = event
            self.write2log(event)
        return True

    def build_tree(self):
        root = self.events
        result, merge = self.__build_tree_fromlist(root)
        while merge:
            root = result
            result, merge = self.__build_tree_fromlist(root)
        ret = {}
        for key in root:
            ret[key] = root[key].dict()
        return ret

    def __build_tree_fromlist(self, events: dict[str, ContainEvent]):
        root = {}
        merge = False
        for key in events.keys():
            a = events[key]
            if a.isRootNode():
                root[a.pid] = a
                continue
            added = False
            for key2 in root:
                parent = root[key2]
                node = parent.find(a)
                if node != None:
                    merge = True
                    node.addchild(a)
                    added = True
                    break
            if not added:
                b = ContainEvent()
                root[a.ppid] = b
                b.pid = a.ppid
                b.addchild(a)
        return root, merge

    def save(self,args=None):
        self.fixcmdline(args)
        self.openfile(None).flush()
        root = self.build_tree()
        # print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",self.treename)
        if root != None:
            import json
            sss = json.dumps(root, indent=4,sort_keys= False)
            fp = open(self.treename, "w")
            fp.write(sss)
            fp.flush()
            fp.close()

    def rm(self):
        import os
        try:
            os.remove(self.filename)
        except:
            pass
        try:
            os.remove(self.treename)
        except:
            pass


class loggerSecspace(logger):
    def add(self, event: ContainEvent):
        inContainer = False
        if event.comm == "secspace" or event.comm == "entersecspace" or event.comm == "systemd-nspawn":
            import time
            # 打印当前时间
            st = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.openfile(event.comm).write(
                "\n\n%s----------------------------------\n" % (st))
            inContainer = True
            hasParent = event.ppid in self.ppid
            if hasParent == False:
                event.rootnode = True
        elif event.ppid in self.ppid:
            inContainer = True
        if inContainer:
            yes = event.pid in self.events
            if yes == False:
                # namespace_pid = get_nspid_from_status(event.pid)
                # event.ns_pid = namespace_pid
                namespace_pid = event.ns_pid
                if namespace_pid != None:
                    exe = get_exe(event.pid)
                    if exe != None:
                        exe = os.path.basename(exe)
                    else:
                        exe = "????=%d" % (event.pid)
                    print("%-50s " % (exe),
                          namespace_pid,event.pid, event.cmdline)
            return super()._add(event)
        return False

    def save(self,args=None):
        self.fixcmdline(args)
        for e in self.events.values():
            self.write2log(e)
        super().save()


if __name__ == "__main__":
    a = logger("logging", False)
    a.save()
    pass
