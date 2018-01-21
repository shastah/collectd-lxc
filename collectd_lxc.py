#!/usr/bin/env python2.7

import glob
import os
import re
import subprocess
from nsenter import Namespace

CONFIG = {'separator': '_',
          'dsname': ('lxc', '%USERID%', '%CONTAINER%'),
          'collectblkio': True,
          'collectcpu': True,
          'collectmemory': True,
          'collectnet': True, }


def config_callback(cfg):
    '''Used as callback when collectd configures plugins'''
    collectd.info('Configuring lxc plugin')
    global CONFIG
    for node in cfg.children:
        key = node.key.lower()
        val = node.values
        if key == 'separator':
            CONFIG[key] = val[0]
        elif key == 'dsname':
            CONFIG[key] = val
        elif key in ['collectblkio', 'collectcpu',
                     'collectmemory', 'collectnet']:
            if isinstance(val[0], bool):
                CONFIG[key] = val[0]
            else:
                CONFIG[key] = str_to_bool(val[0])
    for key in CONFIG:
        collectd.debug("Config: {0} = {1}".format(key, str(CONFIG[key])))


def init_callback():
    '''Used as callback when collectd initializes this plugin'''
    collectd.info('Initializing lxc plugin')


def str_to_bool(string):
    '''Convert string to boolean'''
    truevals = ['true', '1', 'yes']
    return (string is not None and string.lower() in truevals)


def collect_anything():
    '''Return True if at least one metric is to be collected'''
    items = ['collectblkio', 'collectcpu', 'collectmemory', 'collectnet']
    return sum([CONFIG[item] for item in items]) > 0


def get_blkdev_name(minmaj):
    '''Given major:minor device, return a name as friendly as possible'''
    devname = minmaj
    # Try "friendly" names first, if this is LVM, we might have
    # vgname-lvname in dm/name
    try:
        with open('/sys/dev/block/{0}/dm/name'.format(minmaj), 'r') as f:
            devname = f.readline().rstrip()
    except:
        re_dev = re.compile('^DEVNAME=(?P<devname>.+)$', re.MULTILINE)
        try:
            with open('/sys/dev/block/{0}/uevent'.format(minmaj), 'r') as f:
                devname = re_dev.search(f.read()).group('devname')
        except:
            devname = minmaj
    devname = re.sub("[^a-zA-Z0-9]", '_', devname)
    return devname


def get_task_id_by_cgroup(cgroup_path):
    '''Return first ID from /tasks or /init.scope/tasks'''
    tasks_paths = []
    tasks_paths.append(os.path.join(cgroup_path, 'tasks'))
    tasks_paths.append(os.path.join(cgroup_path, 'init.scope', 'tasks'))
    for tasks in tasks_paths:
        try:
            with open(tasks, 'r') as f:
                # First PID is as good as any other
                task_id = f.readline().rstrip()
                return task_id
        except:
            continue
    collectd.debug("cannot get task_id " +
                   "from cgroup path {0}".format(cgroup_path))
    return None


def get_proc_net_dev_by_task_id(task_id):
    '''Get /proc/net/dev contents from inside a container via its net ns'''
    if not task_id:
        return None
    try:
        with Namespace(task_id, 'net'):
            # To read network metric in namespace,
            # "open" method don't work with namespaces
            network_data = subprocess.check_output(['cat', '/proc/net/dev'])
            return network_data.split('\n')
    except:
        collectd.debug("cannot get /proc/net/dev " +
                       "from netns for pid {0}".format(task_id))
        return None


def get_ds_name(user_id, container_name):
    '''Build data source name based on configured template'''
    dscomponents = []
    for string in CONFIG['dsname']:
        if string == '%USERID%':
            dscomponents.append('{0}'.format(user_id))
        elif string == '%CONTAINER%':
            dscomponents.append(container_name)
        else:
            dscomponents.append(str(string))
    return CONFIG['separator'].join(dscomponents)


def collect_net(metric_root, dsn):
    '''Collect network stats and dispatch them'''
    task_id = get_task_id_by_cgroup(metric_root)
    network_data = get_proc_net_dev_by_task_id(task_id)
    if not network_data:
        return
    # HEAD OF /proc/net/dev :
    # Inter-|Receive                                                |Transmit
    # face  |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
    for line in network_data[2:]:
        if line.strip() == "":
            continue
        iface = line.strip().split(':')[0]
        rx_data = line.strip().split(':')[1].split()[0:7]
        tx_data = line.strip().split(':')[1].split()[8:15]

        rx_bytes = int(rx_data[0])
        tx_bytes = int(tx_data[0])

        rx_packets = int(rx_data[1])
        tx_packets = int(tx_data[1])

        rx_errors = int(rx_data[2])
        tx_errors = int(tx_data[2])

        values = collectd.Values(plugin_instance="net", type="if_octets",
                                 plugin=dsn)
        values.dispatch(type_instance=iface, values=[rx_bytes, tx_bytes])

        values = collectd.Values(plugin_instance="net", type="if_packets",
                                 plugin=dsn)
        values.dispatch(type_instance=iface, values=[rx_packets, tx_packets])

        values = collectd.Values(plugin_instance="net", type="if_errors",
                                 plugin=dsn)
        values.dispatch(type_instance=iface, values=[rx_errors, tx_errors])
    return


def collect_cpu(metric_root, dsn):
    '''Collect CPU stats and dispatch them'''
    srcfile = os.path.join(metric_root, 'cpuacct.stat')
    with open(srcfile, 'r') as f:
        lines = f.read().splitlines()

    cpu_user = 0
    cpu_system = 0

    for line in lines:
        data = line.split()
        if data[0] == "user":
            cpu_user = int(data[1])
        elif data[0] == "system":
            cpu_system = int(data[1])

    values = collectd.Values(plugin_instance="cpu", type="cpu", plugin=dsn)
    values.dispatch(type_instance="user", values=[cpu_user])
    values.dispatch(type_instance="system", values=[cpu_system])


def collect_memory(metric_root, dsn):
    '''Collect memory stats and dispatch them'''
    srcfile = os.path.join(metric_root, 'memory.stat')
    with open(srcfile, 'r') as f:
        lines = f.read().splitlines()

    mem_rss = 0
    mem_cache = 0
    mem_swap = 0

    for line in lines:
        data = line.split()
        if data[0] == "total_rss":
            mem_rss = int(data[1])
        elif data[0] == "total_cache":
            mem_cache = int(data[1])
        elif data[0] == "total_swap":
            mem_swap = int(data[1])

    values = collectd.Values(plugin_instance="memory", type="memory",
                             plugin=dsn)
    values.dispatch(type_instance="rss", values=[mem_rss])
    values.dispatch(type_instance="cache", values=[mem_cache])
    values.dispatch(type_instance="swap", values=[mem_swap])


def collect_blkio(metric_root, dsn):
    '''Collect blkio stats and dispatch them'''
    rgxp = r'^ (?P<dev> [0-9:]+ ) \s {0} \s (?P<val> [0-9]+ ) $'
    re_templ = lambda kw: re.compile(rgxp.format(kw),
                                     flags=re.VERBOSE | re.MULTILINE)
    def parse(regexp, s):
        d = {}
        intify = lambda dev_val: (dev_val[0], int(dev_val[1]))
        d.update(map(intify, regexp.findall(s)))
        return d
    parse_reads = lambda s: parse(re_templ("Read"), s)
    parse_writes = lambda s: parse(re_templ("Write"), s)
    # write metrics are slightly irrelevant actually, because writes
    # are only accounted when they are not buffered. So meaningful
    # results are only obtained for direct/unbuffered IO.
    srcfile = os.path.join(metric_root, 'blkio.throttle.io_service_bytes')
    try:
        with open(srcfile, 'r') as f:
            byte_lines = f.read()
            all_bytes_read = parse_reads(byte_lines)
            all_bytes_write = parse_writes(byte_lines)
        for k in all_bytes_read:
            devname = get_blkdev_name(k)
            values = collectd.Values(plugin_instance="blkio",
                                     type="disk_octets",
                                     plugin=dsn)
            values.dispatch(type_instance=devname,
                            values=[all_bytes_read[k], all_bytes_write[k]])
    except:
        collectd.debug("cannot parse {0}".format(srcfile))
        pass

    srcfile = os.path.join(metric_root, 'blkio.throttle.io_serviced')
    try:
        with open(srcfile, 'r') as f:
            ops_lines = f.read()
            all_ops_read = parse_reads(ops_lines)
            all_ops_write = parse_writes(ops_lines)
        for k in all_bytes_read:
            devname = get_blkdev_name(k)
            values = collectd.Values(plugin_instance="blkio",
                                     type="disk_ops",
                                     plugin=dsn)
            values.dispatch(type_instance=devname,
                            values=[all_ops_read[k], all_ops_write[k]])
    except:
        collectd.debug("cannot parse {0}".format(srcfile))
        pass


def read_callback(input_data=None):
    '''Used every time collectd polls for data'''
    # Avoid doing expensive stuff below if there's nothing to collect
    if not collect_anything():
        return

    root_lxc_cgroup = glob.glob("/sys/fs/cgroup/*/lxc/*/")
    unprivilege_lxc_cgroup = glob.glob("/sys/fs/cgroup/*/*/*/*/lxc/*/")

    cgroup_lxc = root_lxc_cgroup + unprivilege_lxc_cgroup

    metrics = dict()

    # Get all stats by container group by user
    rgxp = r'/sys/fs/cgroup/'
    rgxp += r'(?P<type>[a-zA-Z_,]+)/'
    rgxp += r'(?:user/(?P<user_id>[0-9]+)\.user/[a-zA-Z0-9]+\.session/)?lxc/'
    rgxp += r'(?P<container_name>.*)/'
    for cgroup_lxc_metrics in cgroup_lxc:
        m = re.search(rgxp, cgroup_lxc_metrics)
        user_id = int(m.group("user_id") or 0)
        stat_type = m.group("type")
        container_name = m.group("container_name")
        if user_id not in metrics:
            metrics[user_id] = dict()
        if container_name not in metrics[user_id]:
            metrics[user_id][container_name] = dict()
        metrics[user_id][container_name][stat_type] = cgroup_lxc_metrics

    for user_id in metrics:
        for container_name in metrics[user_id]:
            dsn = get_ds_name(user_id, container_name)
            processed_network = False

            for metric in metrics[user_id][container_name]:
                metric_root = metrics[user_id][container_name][metric]

                # there is no separate cgroup for network (the way we're
                # interested in it), but we need container->PID mapping,
                # so we will reuse metric_root of whatever metric that
                # happens to be the first one;
                if not processed_network and CONFIG['collectnet']:
                    # we should only do it once per container
                    processed_network = True
                    collect_net(metric_root, dsn)

                if metric == "memory" and CONFIG['collectmemory']:
                    collect_memory(metric_root, dsn)

                if metric == "cpuacct" and CONFIG['collectcpu']:
                    collect_cpu(metric_root, dsn)

                if metric == "blkio" and CONFIG['collectblkio']:
                    collect_blkio(metric_root, dsn)


if __name__ == '__main__':
    # for commandline debugging
    def print_to_stdout(string):
        print(string)
    # Mimic Collectd Values object
    class Values(object):
        def __init__(self, **kwargs):
            self.__dict__["_values"] = kwargs
        def __setattr__(self, key, value):
            self.__dict__["_values"][key] = value
        def dispatch(self, **kwargs):
            values = self._values.copy()
            values.update(kwargs)
            print(values)

    import types
    collectd = types.ModuleType("collectd")
    collectd.Values = Values
    collectd.info = print_to_stdout

    read_callback()
else:
    import collectd
    collectd.register_config(config_callback)
    collectd.register_init(init_callback)
    collectd.register_read(read_callback)
