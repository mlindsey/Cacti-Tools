#!/usr/bin/env python
"""Queries Cacti DB and RRD store to aggregate data and output in useful formats.
Is useful as an alternative to DSStats."""

# -*- coding: ascii -*-

import base64
import os
import socket
import sys
import traceback
import time
import urllib
import re
import MySQLdb
import simplejson

from optparse import OptionParser

def funcname():
    # so we don't have to keep doing this over and over again.
    return sys._getframe(1).f_code.co_name

def init():
    # collect option information, display help text if needed, set up debugging
    parser = OptionParser()
    default = {}
    try:
        config = open('/usr/share/cacti/include/config.php', 'r').read()
    except:
        default['host'] = 'localhost'
        default['db'] = 'cacti'
        default['user'] = 'cacti'
        default['password'] = 'cacti'
    else:
        default['host'] = config.split('database_hostname')[1].split('"')[1]
        default['db'] = config.split('database_default')[1].split('"')[1]
        default['user'] = config.split('database_username')[1].split('"')[1]
        default['password'] = config.split('database_password')[1].split('"')[1]
    parser.add_option("--name", type="string", dest="name",
                            help="Database hostname to connect to. Default=%s" % (default['host']),
                            default=default['host'])
    parser.add_option("--database", type="string", dest="db",
                            help="Database to connect to. Default=%s" % (default['db']),
                            default=default['db'])
    parser.add_option("--user", type="string", dest="user",
                            help="User to connect to as. Default=%s" % (default['user']),
                            default=default['user'])
    parser.add_option("--password", type="string", dest="password",
                            help="Password to connect with. Default=<redacted>",
                            default=default['password'])
    parser.add_option("-d", "--rradir", type="string", dest="rradir",
                            default="/usr/share/cacti/rra", help="RRA directory, default: /usr/share/cacti/rra")
    parser.add_option("-r", "--rrdtool", type="string", dest="rrdtool",
                            default="/usr/local/bin/rrdtool",
                            help="RRDTool binary, default: /usr/local/bin/rrdtool")
    parser.add_option("--cmdb", type="string", dest="cmdb",
                            help="JSON supplying CMDB.")
    parser.add_option("-H", "--host", type="string", dest="host",
                            help="Host template to poll")
    parser.add_option("--product", type="string", dest="product",
                            help="Only poll hosts matching this product.")
    parser.add_option("--purpose", type="string", dest="purpose",
                            help="Only poll hosts matching this purpose.")
    parser.add_option("--environment", type="string", dest="environment",
                            help="Only poll hosts matching this environment")
    parser.add_option("-D", "--data", type="string", dest="data",
                            help="Data template to poll")
    parser.add_option("-S", "--source", type="string", dest="source",
                            help="Data source inside rrd to use.  Defaults to first if not passed.")
    parser.add_option("-s", "--start", type="int", dest="start",
                            default="-86400",
                            help="Start time, default: -86400")
    parser.add_option("-e", "--end", type="int", dest="end",
                            default="0",
                            help="End time, default: 0")
    parser.add_option("-t", "--toss", type="int", dest="toss",
                            help="Toss data that matches this value.")
    parser.add_option("-m", "--multiply", type="float", dest="multiply",
                            default="1",
                            help="multiply data by this number")
    parser.add_option("-U", "--upperrange", type="float", dest="upperrange",
                            help="Toss any data above this value.")
    parser.add_option("-L", "--lowerrange", type="float", dest="lowerrange",
                            help="Toss any data below this value.")
    parser.add_option("-u", "--upperpercent", type="float", dest="upperpercent",
                            default="99.5",
                            help="Upper range data percent to keep, removes nasty spikes.  Default: 99.5")
    parser.add_option("-l", "--lowerpercent", type="float", dest="lowerpercent",
                            default="0.5",
                            help="Lower range data percent to keep, removes nasty spikes.  Default: 0.5")
    parser.add_option("-c", "--cf", type="string", dest="cf",
                            default="AVERAGE",
                            help="CF to poll, default: AVERAGE")
    parser.add_option("-n", "--cache", type="string", dest="cache",
                            help="Optional filter for name_cache field.")
    parser.add_option("-N", "--notcache", type="string", dest="notcache",
                            help="Optional negative filter for name_cache field.")
    parser.add_option("--listfiles", action="store_true", dest="listfiles",
                            help="List matched files, then exit.")
    parser.add_option("--perhost", action="store_true", dest="perhost",
                            help="Print out per host statistics.")
    parser.add_option("--cpu", action="store_true", dest="cpu",
                            help="Print CPU utilization percentage.  Ignores --data and --source.  Output is average for time slice.")
    parser.add_option("--memory", action="store_true", dest="memory",
                            help="Print Memory utilization percentage.  Ignores --data and --source.  Output is average for time slice.")
    parser.add_option("--swap", action="store_true", dest="swap",
                            help="Print swap utilization percentage.  Ignores --data and --source.  Output is average for time slice.")
    parser.add_option("--disk", action="store_true", dest="disk",
                            help="Print disk utilization stats.  Ignores --data, --source, -n and -N; assumes --perhost.  Output is last for time slice.")
    parser.add_option("--average", action="store_true", dest="average",
                            help="Print average")
    parser.add_option("--minimum", action="store_true", dest="minimum",
                            help="Print minimum")
    parser.add_option("--maximum", action="store_true", dest="maximum",
                            help="Print maximum")
    parser.add_option("--total", action="store_true", dest="total",
                            help="Print average total per file")
    parser.add_option("--fulltotal", action="store_true", dest="fulltotal",
                            help="Print total")
    parser.add_option("--last", action="store_true", dest="last",
                            help="Print last submitted data.")
    parser.add_option("--number", action="store_true", dest="number",
                            help="Print number of data points.")
    parser.add_option("--files", action="store_true", dest="files",
                            help="Print number of files (servers)")
    parser.add_option("--time", action="store_true", dest="time",
                            help="Print number of seconds of good data")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                            default=False,
                            help="print debug messages to stderr")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet",
                            default=False,
                            help="Suppress certain informatative messages.")
    global options
    (options, args) = parser.parse_args()

    if options.verbose: sys.stderr.write(">>DEBUG sys.argv[0] running in " +
                            "debug mode\n")
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() + 
                            "()\n")
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    exit = 0
    if (options.cpu and options.memory) or (options.cpu and options.disk) or (options.cpu and options.swap) or \
        (options.disk and options.memory) or (options.disk and options.swap) or (options.memory and options.swap):
        print "--cpu, --memory, --swap, and --disk are mututally exclusive."
        exit = 1
    elif options.cpu or options.memory or options.disk or options.swap:
        # will be overwritten later
        options.quiet = True
        options.data = 'CPU Idle'
    if not options.host and not (options.product or options.purpose or options.environment):
        print "Must supply at least one of -H, --product, --environment, or --purpose."
        exit = 1
    if not options.data:
        print "-D is not optional."
        exit = 1
    if options.cache:
        if options.cache.count(';'):
            print "Semicolon not allowed in cache filters."
            exit = 1
    if options.notcache:
        if options.notcache.count(';'):
            print "Semicolon not allowed in notcache filters."
            exit = 1

    if exit:
        parser.print_help()
        sys.exit(-1)

    if options.end == 0:
        options.start = options.start  - 600
        options.end = options.end - 600

    return options

def init_db():
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() + 
                            "()\n")
    conn = MySQLdb.connect (host = options.host,
                            user = options.user,
                            passwd = options.passwd,
                            db = options.db)
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return conn

def do_sql(sql):
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() + 
                            "()\n")
    conn = init_db()
    cursor = conn.cursor()
    if options.verbose: print "%s, %s" % (sql, conn)

    cursor.execute(sql)
    val = cursor.fetchall()
    conn.commit()
    conn.close()
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return val

def get_cmdb_hosts():
    """Function included to use as a guideline for anyone wanting to link
    this into their CMDB."""
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() +
                            "()\n")
    url="http://" + options.cmdb + "/servers/data/?format=json"
    if options.product: url += "&product__name__exact=%s" % (options.product)
    if options.purpose: url += "&purpose__name__exact=%s" % (options.purpose)
    if options.environment: url += "&environment__name__exact=%s" % (options.environment)
    if options.verbose: print "Grabbing hostlist from", url
    response=urllib.urlopen(url).readlines()
    hosts = simplejson.dumps(response)
    hosts = simplejson.loads(hosts)[0]
    hostlist = []
    for host in simplejson.loads(hosts):
        hostlist.append(host['name'])
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return hostlist

def find_host_template():
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() +
                            "()\n")
    host_templates = list(do_sql('select name from host_template'))
    for template in options.host.split(','):
        if not host_templates.count((template,)):
            print "Host template '%s' not in cacti database." % (template)
            print "Valid templates are:"
            for template in host_templates: print "'%s'" % (template[0])
            print "Please fix your error and try again."
            sys.exit(-1)
        if options.verbose: print "Found host template %s." % (template)
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() +
                            "()\n")

def find_data_template():
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() +
                            "()\n")
    if not options.host:
        hostlist = ['']
    else:
        hostlist = options.host.split(',')
    datalist = options.data.split(',')
    for host in hostlist:
        for data in datalist:
            sql = '''SELECT data_local.id
                FROM data_local, host, host_template, data_template
                WHERE data_local.host_id=host.id
                AND host.host_template_id=host_template.id
                AND data_local.data_template_id=data_template.id'''
            if options.host: sql += " AND host_template.name='%s'" % (host)
            if options.data: sql += " AND data_template.name='%s'" % (data)
            sql += " GROUP BY data_local.id"
            data_templates = list(do_sql(sql))
            if (len(data_templates) == 0):
                print "No matches for the combination of host template '%s' and data template '%s'." % (host, data)
                sql = '''SELECT data_template.name
                    FROM data_local, host, host_template, data_template
                    WHERE data_local.host_id=host.id
                    AND host.host_template_id=host_template.id
                    AND data_local.data_template_id=data_template.id'''
                if options.host: sql += " AND host_template.name='%s'" % (host)
                sql += " GROUP BY data_template.name"
                if options.host: print "Valid data templates for that host template are:"
                if not options.host: print "Valid data templates for NULL host template are:"
                data_templates = list(do_sql(sql))
                for template in data_templates: print "'%s'" % (template[0])
                print "Please fix your error and try again."
                sys.exit(-1)

        if options.verbose: print "Found data template %s/%s." % (host, data)

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() +
                            "()\n")

def find_data_source():
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() +
                            "()\n")
    if not options.host:
        hostlist = ['']
    else:
        hostlist = options.host.split(',')
    datalist = options.data.split(',')
    x = -1
    for data in datalist:
        x += 1
        data_source_names = []
        for host in hostlist:
            sql = '''SELECT data_template_rrd.data_source_name
                FROM data_template_rrd, data_template, data_local, host, host_template
                WHERE data_template_rrd.data_template_id=data_template.id
                AND data_template_rrd.local_data_id=data_local.id
                AND data_local.host_id=host.id
                AND host.host_template_id=host_template.id'''
            if options.host: sql += " AND host_template.name='%s'" % (host)
            if options.data: sql += " AND data_template.name='%s'" % (data)
            sql += " GROUP BY data_template_rrd.data_source_name"
            dsn = do_sql(sql)
            for ds in dsn: data_source_names.append(ds[0])
            if options.source:
                for source in options.source.split('!')[x].split(','):
                    if (source not in data_source_names):
                        print "Data Source '%s/%s/%s' not found in cacti database." % (host, data, source)
                        print "Valid DS options for your data template are:"
                        for ds in data_source_names: print "'%s'" % (ds)
                        print "Please fix your error and try again."
                        sys.exit(-1)
                    if options.verbose: print "Found data source '%s/%s/%s'." % (host, data, source)
            else:
                if options.verbose: print "No Source passed, using '%s'..  Hopefully this is ok." % (data_source_names[0])
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() +
                            "()\n")


def get_data():
    if options.verbose: sys.stderr.write(">>DEBUG start  - " + funcname() +
                            "()\n")
    if options.host: find_host_template()
    find_data_template()
    find_data_source()
    if (options.product or options.purpose or options.environment):
        global hostlist
        try:
            hostlist
        except NameError:
            hostlist = get_cmdb_hosts()
    else:
        hostlist = ['x']
    if options.verbose: print "Hostlist: ", hostlist
    host_filter = ''
    cache_filter = ''
    if options.cache:
        for cache in str(options.cache).split(','):
            cache_filter += " AND data_template_data.name_cache LIKE '%s' " % (cache)
    if options.notcache:
        for cache in str(options.notcache).split(','):
            cache_filter += " AND data_template_data.name_cache NOT LIKE '%s' " % (cache)
    value_dict = {}
    host_filter = ""
    if len(hostlist) == 0:
        print "No hosts in hostlist."
        sys.exit(0)
    if options.verbose:
        print "Hostlist\n%s" % (hostlist)
    for host in hostlist:
        # Graphing by ASDB entries.
        if host != 'x':
            host_filter = " AND (host.hostname = '%s')" % (host)

        sql = "SELECT data_template_data.data_source_path FROM data_template_data, data_local, "
        sql += "data_template, host, host_template WHERE data_template_data.local_data_id = data_local.id "
        sql += "AND data_local.data_template_id = data_template.id and host.disabled != 'on' "
        sql += "AND host.host_template_id = host_template.id AND data_local.host_id = host.id"
        if options.host: sql += " AND host_template.name = '%s'" % (options.host)
        if options.data: sql += " AND data_template.name='%s'" % (options.data)
        sql += host_filter
        sql += " %s GROUP BY data_template_data.name_cache" % (cache_filter)

        files = do_sql(sql)

        if len(files) == 0:
            if host != 'x':
                if not options.quiet: print "No files matched for host %s" % (host)
            else:
                print "No files matched"
                sys.exit(-1)

        if options.verbose: print files

        values = []
        filehash = {}
        seconds = 0

        value_dict[host] = {}
        for file in files:
            file = file[0]
            value_dict[host][file.split('/')[-1]] = {}
            starttime = 0
            endtime = 0
            file = file.replace('<path_rra>', options.rradir)
            cmd = '%s fetch %s %s -s %s -e %s' % (options.rrdtool, file, options.cf, options.start, options.end)
            if options.verbose: print cmd
            output = os.popen(cmd).readlines()
            dsources = output[0].split()
            if not options.source:
                source = 0
            else:
                try:
                    source = dsources.index(options.source)
                except:
                    print "Invalid data source, options are: %s" % (dsources)
                    sys.exit(0)
            
            ## collect last update data.
            #cmd = '%s lastupdate %s' % (options.rrdtool, file)
            #if options.verbose: print cmd
            #lastoutput = os.popen(cmd).readlines()
            #lastoutput = lastoutput[2]
            #lastoutput = lastoutput.split()
            #try:
            #    last = float(lastoutput[source+1])
            #except:
            #    last = 0

            data = output[3:]
            for val in data:
                val = val.split()
                time = int(val[0][:-1])
                val = float(val[source+1])
                # make sure it's not invalid numerical data, and also an actual number
                ok = 1
                if options.lowerrange:
                    if val < options.lowerrange: ok = 0
                if options.upperrange:
                    if val > options.upperrange: ok = 0
                if ((options.toss and val != options.toss and val == val) or val == val) and ok:
                    if starttime == 0:
                        # this should be accurate for up to six months in the past
                        if options.start < -87000:
                            starttime = time - 1800
                        else:
                            starttime = time - 300
                    else:
                        starttime = endtime
                    endtime = time
                    filehash[file] = 1
                    # Too noisy!
                    #if options.verbose: print "%s, %s" % (val, type(val))
                    val = val * options.multiply
                    values.append(val)
                    seconds = seconds + (endtime - starttime)

            numfiles = len(filehash)
            num = len(values)

            if num == 0:
                continue

            tossed = []
            last = values[-1]
            values.sort()

            if options.lowerpercent > 0:
                lowerpercent = int(num * options.lowerpercent / 100)
                tossed = tossed + values[0:lowerpercent]
            else:
                lowerpercent = -1

            if options.upperpercent < 100:
                upperpercent = int(num * options.upperpercent / 100)
                tossed = tossed + values[upperpercent::]
            else:
                upperpercent = -1

            values = values[lowerpercent+1:upperpercent]

            total = 0.0
            for val in values:
                total += val
            if host != 'x':
                value_dict[host][file.split('/')[-1]] = {'values' : values, 'total' : total, 'seconds' : seconds, 'last': last}
            else:
                value_dict['x'][file.split('/')[-1]] = {'values' : values, 'total' : total, 'seconds' : seconds, 'last': last}
    
    try:
        last
    except NameError:
        last = 0
    total_dict = {'values' : [], 'total' : 0, 'numfiles' : 0, 'seconds' : 0, 'last' : last}

    for host in value_dict:
        for file in value_dict[host]:
            try:
                total_dict['values'] += value_dict[host][file]['values']
                total_dict['numfiles'] += 1
                total_dict['total'] += value_dict[host][file]['total']
                total_dict['seconds'] += value_dict[host][file]['seconds']
            except:
                if options.verbose:
                    print "Missing Valuedata!  Continuing, and holding onto pants."

            if options.listfiles:
                print file
    if len(total_dict['values']) == 0 and not options.memory:
        print "No values in data set."
        sys.exit(-1)

    if options.listfiles:
        sys.exit(0)

    total_dict['values'].sort()

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() +
                            "()\n")
    return total_dict, value_dict

options = init()
total_dict = {}
value_dict = {}

if options.cpu:
    for data in ['CPU Idle', 'CPU Interrupt', 'CPU Kernel', 'CPU Nice', 'CPU System', 'CPU User']:
        options.data = data
        options.source = None
        total_dict[data], value_dict[data] = get_data()
    if options.perhost:
        print "hostname,cpuavg%"
        value_total = {}
        idle_total = {}
        for host in value_dict['CPU Idle']:
            value_total[host] = 0
            idle_total[host] = 0
        for key in value_dict:
            for host in value_dict[key]:
                for file in value_dict[key][host]:
                    try:
                        value_total[host] += value_dict[key][host][file]['total']
                    except:
                        if not options.quiet:
                            print "Error adding 'total' from\nkey:%s\nhost:%s\nfile:%s\n'%s'" % \
                                    (key, host, file, value_dict[key][host][file])
                    else:
                        if key == 'CPU Idle':
                            idle_total[host] += value_dict[key][host][file]['total']
        for host in value_total:
            try:
                print "%s,%.2f" % (host, 100-(idle_total[host]/value_total[host])*100)
            except:
                print "%s,NaN" % (host)
    else:
        total_total = 0
        for key in total_dict.keys():
            total_total += total_dict[key]['total']
        print "CPU%% %.2f" % (100-(total_dict['CPU Idle']['total']/(total_total))*100)
    
elif options.memory:
    options.data = 'FreeBSD - Memory'
    total_dict = {}
    value_dict = {}
    for source in ['fBSDmemcache', 'fBSDmemfree', 'fBSDmeminactive', 'fBSDmemtotal']:
        options.source = source
        total_dict[source], value_dict[source]  = get_data()
    options.source = None
    options.data = 'ucd/net - Memory - Free'
    total_dict['free'], value_dict['free']  = get_data()
    options.data = 'ucd/net - Memory - Total'
    total_dict['total'], value_dict['total']  = get_data()
    if options.perhost:
        print "hostname,memavg%"
        value_total = {}
        free_total = {}
        for host in set(value_dict['fBSDmemtotal'].keys() + value_dict['total'].keys()):
            value_total[host] = 0
            free_total[host] = 0
        for key in value_dict:
            for host in value_dict[key]:
                for file in value_dict[key][host]:
                    try:
                        if key == 'fBSDmemtotal' or key == 'total':
                            value_total[host] += value_dict[key][host][file]['total']
                        else:
                            free_total[host] += value_dict[key][host][file]['total']
                    except:
                        if not options.quiet:
                            print "Error adding 'total' from\nkey:%s\nhost:%s\nfile:%s\n'%s'" % \
                                    (key, host, file, value_dict[key][host][file])
        for host in value_total:
            try:
                print "%s,%.2f" % (host, 100-(free_total[host]/value_total[host])*100)
            except:
                print "%s,NaN" % (host)
    else:
        if len(total_dict['total']['values']):
            print "Memory%% %.2f" % (100-((total_dict['free']['total']/total_dict['total']['total']) * 100))
        else:
            print "Memory%% %.2f" % (100-((total_dict['fBSDmemcache']['total']+total_dict['fBSDmemfree']['total']+
                                        total_dict['fBSDmeminactive']['total'])/(total_dict['fBSDmemtotal']['total']))*100)
elif options.disk:
    options.quiet = True
    options.data = 'ucd/net - Hard Drive Space'
    total_dict = {}
    value_dict = {}
    mount_dict = {}
    print "hostname:/mount,used%,free,used,total"
    hostlist = get_awesome_hosts()
    for host in hostlist:
        total_dict[host] = {}
        value_dict[host] = {}
        mount_dict[host] = {}
        sql = "SELECT name_cache FROM data_template_data WHERE name_cache LIKE '%s - Partition - %%'" % (host)
        mounts = do_sql(sql)
        for mount in mounts:
            mount = mount[0].split()[-1]
            sql = "SELECT field_value FROM host_snmp_cache WHERE host_id = (SELECT id FROM host WHERE hostname = '%s') AND field_name LIKE 'dskPath' AND snmp_index = (SELECT snmp_index FROM host_snmp_cache WHERE field_value = '%s' AND field_name = 'dskDevice' AND snmp_query_id = 2 AND host_id = (SELECT id FROM host WHERE hostname = '%s') LIMIT 1)" % (host, mount, host)
            try:
                path = do_sql(sql)[0][0]
            except:
                path = mount

            total_dict[host][mount] = {}
            value_dict[host][mount] = {}
            mount_dict[host][mount] = path

            options.cache = "%s %% %s" % (host, mount)
            for source in ['hdd_free', 'hdd_used']:
                options.source = source
                total_dict[host][mount][source] = {}
                value_dict[host][mount][source] = {}
                total_dict[host][mount][source], value_dict[host][mount][source] = get_data()
            free = total_dict[host][mount]['hdd_free']['last']
            used = total_dict[host][mount]['hdd_used']['last']
            total = free + used
            try:
                usedper = 100 - ((float(free) / float(total)) * 100.0)
            except:
                usedper = 0
            print "%s:%s,%2.2f,%s,%s,%s" % (host, path, usedper, free, used, total)
elif options.swap:
    total_dict = {}
    value_dict = {}
    for data in ['Available', 'Total']:
        options.data = 'ucd/net - %s Swap' % (data)
        options.source = None
        total_dict[data] = {}
        value_dict[data] = {}
        total_dict[data], value_dict[data] = get_data()
    if options.perhost:
        print "hostname,swapavg%"
        value_total = {}
        free_total = {}
        for host in value_dict['Total']:
            value_total[host] = 0
            free_total[host] = 0
        for key in value_dict:
            for host in value_dict[key]:
                for file in value_dict[key][host]:
                    try:
                        if key == 'Total':
                            value_total[host] += value_dict[key][host][file]['total']
                        else:
                            free_total[host] += value_dict[key][host][file]['total']
                    except:
                        if not options.quiet:
                            print "Error adding 'total' from\nkey:%s\nhost:%s\nfile:%s\n'%s'" % \
                                    (key, host, file, value_dict[key][host][file])
        for host in value_total:
            try:
                print "%s,%.2f" % (host, 100-(free_total[host]/value_total[host])*100)
            except:
                print "%s,NaN" % (host)
    else:
        print "Swap%% %.2f" % (100-(total_dict['Available']['total']/total_dict['Total']['total'])*100)

else:
    total_dict, value_dict = get_data()
    if options.perhost:
        print "hostname,avg,min,max,num,numfiles,seconds,total,fulltotal"
        for host in value_dict:
            values = []
            total = 0
            numfiles = 0
            seconds = 0
            for file in value_dict[host]:
                if not value_dict[host][file].has_key('values'):
                    continue
                values += value_dict[host][file]['values']
                total += value_dict[host][file]['total']
                numfiles += 1
                seconds += value_dict[host][file]['seconds']
                last = value_dict[host][file]['last']
            if not len(values):
                continue
            values.sort()
            avg = total/len(values)
            min = values[0]
            max = values[-1]
            num = len(values)
            totalval = total/len(values) * (seconds/numfiles)
            fulltotal = total/len(values) * (seconds)
            print "%s,%s,%s,%s,%s,%s,%s,%s,%s" % \
                (host,avg,min,max,num,numfiles,seconds,totalval,fulltotal)
    else:
        values = total_dict['values']
        total = total_dict['total']
        numfiles = total_dict['numfiles']
        seconds = total_dict['seconds']
        last = total_dict['last']
        if (numfiles == 0):
            print "No files in file list."
            sys.exit(0)
        if options.average: print "avg: %s" % (total/len(values)),
        if options.minimum: print "min: %s" % (values[0]),
        if options.maximum: print "max: %s" % (values[-1]),
        if options.number: print "num: %s" % (len(values)),
        if options.files: print "files: %s" % numfiles,
        if options.time: print "seconds: %s" % seconds,
        if options.total: print "avgsum: %s" % ((total * (seconds / len(values)) / numfiles)),
        if options.fulltotal: print "sum: %s" % (total * (seconds / len(values))),
        if options.last: print "last: %s" % (last),
