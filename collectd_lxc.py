#!/usr/bin/env python2.7

import glob
import os
import re
import subprocess
from nsenter import Namespace

CONFIG = { 'separator': '_',
           'dsname': ('lxc', '%USERID%', '%CONTAINER%'),
           'collectblkio': True,
           'collectcpu': True,
           'collectmemory': True,
           'collectnet': True,
         }


def config_callback(cfg):
    collectd.info('Configuring lxc plugin')
    global CONFIG
    for node in cfg.children:
        k = node.key.lower()
        v = node.values
        if k == 'separator':
            CONFIG[k] = v[0]
        elif k == 'dsname':
            CONFIG[k] = v
        elif k in ['collectblkio', 'collectcpu',
                   'collectmemory', 'collectnet']:
            CONFIG[k] = str_to_bool(v[0])
    for k in CONFIG:
        collectd.debug("Config: {0} = {1}".format(k, str(CONFIG[k])))


def init_callback():
    collectd.info('Initializing lxc plugin')


def str_to_bool(s):
    if s and s.lower() in ['true', '1', 'yes']:
        return True
    else:
        return False


def collect_anything():
    '''Returns True if at least one metric is to be collected'''
    m = ['collectblkio', 'collectcpu', 'collectmemory', 'collectnet']
    return sum([CONFIG[item] for item in m]) > 0


def get_blkdev_name(minmaj):
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
    collectd.debug("cannot get task_id from cgroup path {0}".format(cgroup_path))
    return None


def get_proc_net_dev_by_task_id(task_id):
    if not task_id:
        return None
    try:
        with Namespace(task_id, 'net'):
            # To read network metric in namespace,
            # "open" method don't work with namespaces
            network_data = subprocess.check_output(['cat', '/proc/net/dev'])
            return network_data.split('\n')
    except:
        collectd.debug("cannot get /proc/net/dev from netns for pid {0}".format(task_id))
        return None


def get_ds_name(user_id, container_name):
    ds = []
    for s in CONFIG['dsname']:
        if s == '%USERID%':
            ds.append('{0}'.format(user_id))
        elif s == '%CONTAINER%':
            ds.append(container_name)
        else:
            ds.append(str(s))
    return CONFIG['separator'].join(ds)


def dispatch_network_data(dsn, network_data):
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
    with open(os.path.join(metric_root, 'cpuacct.stat'), 'r') as f:
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


def read_callback(input_data=None):
    # Avoid doing expensive stuff below if there's nothing to collect
    if not collect_anything():
        return

    root_lxc_cgroup = glob.glob("/sys/fs/cgroup/*/lxc/*/")
    unprivilege_lxc_cgroup = glob.glob("/sys/fs/cgroup/*/*/*/*/lxc/*/")

    cgroup_lxc = root_lxc_cgroup + unprivilege_lxc_cgroup

    metrics = dict()

    #Get all stats by container group by user
    for cgroup_lxc_metrics in cgroup_lxc:
        m = re.search("/sys/fs/cgroup/(?P<type>[a-zA-Z_,]+)/(?:user/(?P<user_id>[0-9]+)\.user/[a-zA-Z0-9]+\.session/)?lxc/(?P<container_name>.*)/", cgroup_lxc_metrics)
        user_id = int(m.group("user_id") or 0)
        stat_type = m.group("type")
        container_name = m.group("container_name")
        if user_id not in metrics:
            metrics[user_id] = dict()
        if container_name not in metrics[user_id]:
            metrics[user_id][container_name] = dict()
        metrics[user_id][container_name][stat_type] = cgroup_lxc_metrics

    # foreach user
    for user_id in metrics:
        # foreach container
        for container_name in metrics[user_id]:
            dsn = get_ds_name(user_id, container_name)
            processed_network = False

            for metric in metrics[user_id][container_name]:
                metric_root = metrics[user_id][container_name][metric]

                ### Network
                # there is no separate cgroup for network (the way we're
                # interested in it), but we need container->PID mapping,
                # so we will reuse metric_root of whatever metric that
                # happens to be the first one;
                # don't do it after other cgroups, because some of them
                # do "continue" on errors, which would skip networking
                if not processed_network and CONFIG['collectnet']:
                    # we should only do it once per container
                    processed_network = True
                    task_id = get_task_id_by_cgroup(metric_root)
                    network_data = get_proc_net_dev_by_task_id(task_id)
                    dispatch_network_data(dsn, network_data)
                ### End Network

                ### Memory
                if metric == "memory" and CONFIG['collectmemory']:
                    with open(os.path.join(metric_root, 'memory.stat'), 'r') as f:
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

                    values = collectd.Values(plugin_instance="memory",
                                             type="memory", plugin=dsn)
                    values.dispatch(type_instance="rss", values=[mem_rss])
                    values.dispatch(type_instance="cache", values=[mem_cache])
                    values.dispatch(type_instance="swap", values=[mem_swap])

                ### End Memory

                ### CPU
                if metric == "cpuacct" and CONFIG['collectcpu']:
                    collect_cpu(metric_root, dsn)
                ### End CPU

                ### DISK
                # write metrics are slightly irrelevant actually, because writes
                # are only accounted when they are not buffered. So meaningful
                # results are only obtained for direct/unbuffered IO.
                if metric == "blkio" and CONFIG['collectblkio']:
                    re_templ = lambda kw: re.compile('^ (?P<dev> [0-9:]+ ) \s %s \s (?P<val> [0-9]+ ) $' % kw, flags=re.VERBOSE | re.MULTILINE)
                    def parse(regexp, s):
                        d = {}
                        intify = lambda (dev, val) : (dev, int(val))
                        d.update(map(intify, regexp.findall(s)))
                        return d
                    parse_reads = lambda s : parse(re_templ("Read"), s)
                    parse_writes = lambda s : parse(re_templ("Write"), s)

                    try:
                        with open(os.path.join(metric_root, 'blkio.throttle.io_service_bytes'), 'r') as f:
                            byte_lines = f.read()
                            all_bytes_read = parse_reads(byte_lines)
                            all_bytes_write = parse_writes(byte_lines)
                        for k in all_bytes_read:
                            devname = get_blkdev_name(k)
                            values = collectd.Values(plugin_instance="blkio", type="disk_octets", plugin=dsn)
                            values.dispatch(type_instance=devname, values=[all_bytes_read[k], all_bytes_write[k]])
                    except:
                        collectd.debug("cannot parse {0}/{1}".format(metric_root,
                                                'blkio.throttle.io_service_bytes'))
                        pass

                    try:
                        with open(os.path.join(metric_root, 'blkio.throttle.io_serviced'), 'r') as f:
                            ops_lines = f.read()
                            all_ops_read = parse_reads(ops_lines)
                            all_ops_write = parse_writes(ops_lines)
                        for k in all_bytes_read:
                            devname = get_blkdev_name(k)
                            values = collectd.Values(plugin_instance="blkio", type="disk_ops", plugin=dsn)
                            values.dispatch(type_instance=devname, values=[all_ops_read[k], all_ops_write[k]])
                    except:
                        collectd.debug("cannot parse {0}/{1}".format(metric_root,
                                                'blkio.throttle.io_serviced'))
                        pass



                ### End DISK



if __name__ == '__main__':
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

    read_callback()
else:
    import collectd
    collectd.register_config(config_callback)
    collectd.register_init(init_callback)
    collectd.register_read(read_callback)
