#!/usr/bin/env python
# Takes a script and optional hostname as input, runs said script,
# inspects the output and then builds a full set of data input method,
# data templates, and graph templates.
# Michael Lindsey <mike@5dninja.net>
# 11/18/2009

# -*- coding: ascii -*-

import base64
import md5
import os
import socket
import sys
import traceback
import time
import re
import MySQLdb

from optparse import OptionParser

def funcname():
    # so we don't have to keep doing this over and over again.
    return sys._getframe(1).f_code.co_name

def init():
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
    default['wwwhost'] = socket.gethostname()
    default['height'] = 120
    default['width'] = 500
    default['cf'] = 'average'
    default['rrdmax'] = 1000000000
    default['rrdmin'] = 0
    default['rrdbeat'] = 600
    default['dstype'] = 'gauge'

    # collect option information, display help text if needed, set up debugging
    usage = "usage: %prog [options]\n"
    usage += """example: %prog --script "<path_cacti>/scripts/snmp_extend.sh <hostname> <snmp_community> jstat_jboss-gcutil" --hostname app-server.domain.com\n"""
    usage += """example: %prog --script "<path_cacti>/scripts/snmp_extend.sh <hostname> <snmp_community> jstat_jboss-gcutil" --hostname app-server.domain.com --dstype=gauge --title="JVM GC Summary" --group 'S0,S1,E,O,P!YGC,FGC!YGCT,FGCT,GCT' --friendlies='S0:Survivor 0 % Capacity,S1:Survivor 1 % Capacity,E:Eden % Capacity,YGC:Young GC Events,YGCT:Young GC Time,FGC:Full GC Events,FGCT:Full GC Time,GCT:Total GC Time' --dstypeoverride='YGCT:derive,FGCT:derive,GCT:derive' --templates 'HostTemplate'""" 

    parser = OptionParser(usage=usage)
    parser.add_option("-s", "--script", type="string", dest="script",
                            help="""Script to run for DIM inspection.
Cacti style bracketing for input sources.
Anything other than <path_cacti>, <hostname>, <snmp_community>
will not be handled properly at this time!""")
    parser.add_option("-H", "--hostname", type="string", dest="hostname",
                            help="Hostname to run input script against for validation")
    parser.add_option("--group", type="string", dest="group",
                            help="""CSV style input for DS grouping onto single graphs.
--group 'name1,name2,name3!name2,name6,name12'
to group onto multiple multi-item graphs.  Duplicates ok!""")
    parser.add_option("--height", type="int", dest="height",
                            help="Height of graphs. Default=%s" % (default['height']),
                            default=default['height'])
    parser.add_option("--width", type="int", dest="width",
                            help="Width of graphs. Default=%s" % (default['width']),
                            default=default['width'])
    parser.add_option("--area", action="store_true", dest="area",
                            help="Create Area/Stack type graph instead of line type graph.",
                            default=False)
    parser.add_option("--title", type="string", dest="title",
                            help="Shared DS and Graph Title. Defaults to base of script.")
    parser.add_option("--templates", type="string", dest="templates",
                            help="CSV Host Templates to add new graphs to.")
    parser.add_option("--rrdmax", type="int", dest="rrdmax",
                            help="RRD Maximum for data templates, Default=%s" % (default['rrdmax']),
                            default=default['rrdmax'])
    parser.add_option("--rrdmin", type="int", dest="rrdmin",
                            help="RRD Minimum for data templates, Default=%s" % (default['rrdmin']),
                            default=default['rrdmin'])
    parser.add_option("--rrdbeat", type="int", dest="rrdbeat",
                            help="RRD Heartbeat for data templates, Default=%s" % (default['rrdbeat']),
                            default=default['rrdbeat'])
    parser.add_option("--dstype", type="string", dest="dstype",
                            help="RRD DS type for data templates, Default=%s" % (default['dstype']),
                            default=default['dstype'])
    parser.add_option("--dstypeoverride", type="string", dest="dstypeoverride",
                            help="CSV of DS:Type list for overriding --dstype for individual data sources")
    parser.add_option("--friendly", action="store_true", dest="friendly",
                            help="Prompt for Friendly Names for DS inputs.",
                            default=False)
    parser.add_option("--friendlies", type="string", dest="friendlies",
                            help="CSV of DS:Friendly Name, instead of prompting.")
    parser.add_option("--dbhost", type="string", dest="dbhost",
                            help="Database hostname to connect to. Default=%s" % (default['host']),
                            default=default['host'])
    parser.add_option("--database", type="string", dest="db",
                            help="Database to connect to. Default=%s" % (default['db']),
                            default=default['db'])
    parser.add_option("--www", type="string", dest="wwwhost",
                            help="WWW Host to use in url generation.",
                            default=default['wwwhost'])
    parser.add_option("-u", "--user", type="string", dest="user",
                            help="User to connect to as. Default=%s" % (default['user']),
                            default=default['user'])
    parser.add_option("-p", "--password", type="string", dest="password",
                            help="Password to connect with. Default=<redacted>",
                            default=default['password'])
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                            default=False,
                            help="print debug messages to stderr")
    parser.add_option("--justrun", action="store_true", dest="justrun",
                            default=False,
                            help="Just run the script, don't build templates.")
    global options
    (options, args) = parser.parse_args()
    if options.verbose: sys.stderr.write(">>DEBUG sys.argv[0] running in " +
                            "debug mode\n")
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    if not options.script:
        print "--script is not optional"
        parser.print_help()
        sys.exit(-1)
    if str(options.script).count('<hostname>') and not options.hostname:
        print "If --script includes <hostname> macro, --hostname is not optional."
        parser.print_help()
        sys.exit(-1)
    if str(options.script).count('<path_cacti>'):
        try:
            x = path_cacti()
        except:
            print "Unable to query database for path_cacti macro"
            sys.exit(-1)
    if str(options.script).count('<snmp_community>'):
        try:
            x = snmp_community(options.hostname)
        except:
            print "Failed to query database for snmp_community.  None set for host?"
            sys.exit(-1)
    error = 0
    if options.rrdmax <= options.rrdmin and (options.rrdmax != 0 and options.rrdmin != 0):
        print "--rrdmax MUST be greater than --rrdmin, unless both are 0."
        error += 1
    if options.rrdbeat < 60:
        print "--rrdbeat MUST be greater than or equal to 60"
        error += 1
    dstype_list = ['gauge', 'counter', 'derive', 'absolute']
    options.dstype = str(options.dstype).lower()
    if options.dstype not in dstype_list:
        print "--dstype must be one of %s" % (dstype_list)
        error += 1
    else:
        options.dstype = dstype_list.index(options.dstype) + 1

    if error:
        parser.print_help()
        sys.exit(-1)
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return options

def init_db():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    conn = MySQLdb.connect (host = options.dbhost,
                            user = options.user,
                            passwd = options.password,
                            db = options.db)
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return conn

def do_sql(sql):
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    conn = init_db()
    cursor = conn.cursor()

    for statement in sql.split(';'):
        if options.verbose: print "%s, %s" % (statement, conn)
        cursor.execute(statement)
    val = cursor.fetchall()
    conn.commit()
    conn.close()
    if options.verbose: print val
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return val

def path_cacti():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    path_cacti = do_sql("SELECT value FROM settings WHERE name='path_webroot'")[0][0]
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return path_cacti

def snmp_community(hostname=None):
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    if not hostname:
        sql = "SELECT value FROM settings WHERE name='snmp_community'"
    else:
        sql = "SELECT snmp_community FROM host WHERE hostname='%s'" % (hostname)
    snmp_community = do_sql(sql)[0][0]
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return snmp_community

def run_script():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    script = str(options.script)
    if script.count('<path_cacti>'):
        script = script.replace('<path_cacti>', path_cacti())
    if script.count('<hostname>'):
        script = script.replace('<hostname>', options.hostname)
    if script.count('<snmp_community>'):
        script = script.replace('<snmp_community>', snmp_community(options.hostname))
    print "About to run script for inspection:\n%s" % (script)
    output = os.popen(script).read()
    print "Script output is:\n%s" % (output)
    ds_list = []
    friendly_dict = {}
    for item in output.split():
        item = item.split(':')[0]
        ds_list.append(item)
        if options.friendlies and not options.justrun:
            friendlies = str(options.friendlies)
            if friendlies.startswith("%s:" % (item)):
                friendly_dict[item] = friendlies.split(':')[1].split(',')[0]
            elif ",%s:" % (item) in friendlies:
                friendly_dict[item] = friendlies.split(',%s:' % (item))[1].split(',')[0]
            else:
                friendly_dict[item] = item
        elif options.friendly:
            friendly = raw_input("Friendly name for '%s': " % (item))
            friendly_dict[item] = friendly
        else:
            friendly_dict[item] = item
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return (ds_list, friendly_dict)

def gen_hash(table):
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    hash = ""
    # Needs to be unique
    while hash == "":
        m = md5.new()
        m.update(str(options.script))
        m.update(str(time.time()))
        sql = "SELECT hash FROM %s WHERE hash='%s'" % (table, m.hexdigest())
        result = do_sql(sql)
        if result == ():
            hash = m.hexdigest()
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return hash

def create_dim():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    hash = gen_hash('data_input')
    if options.title:
        name = options.title
    else:
        name = str(options.script).split()[0].split('/')[-1].split('\\')[-1].split('.')[0]
    print "Creating Data Input Method for '%s'" % (name)
    sql = "INSERT INTO data_input VALUES (0, '%s', '%s', '%s', 1)" % \
        (hash, name, options.script)
    do_sql(sql)
    sql = "SELECT id FROM data_input WHERE hash='%s'" % (hash)
    dim_id = do_sql(sql)[0][0]
    for ds in ds_list:
        hash = gen_hash('data_input_fields')
        print "Adding field '%s' to DIM." % (ds)
        sql = "INSERT INTO data_input_fields VALUES (0, '%s', %s, '%s', '%s', " % \
            (hash, dim_id, friendly_dict[ds], ds)
        sql += "'out', 'on', 0, NULL, NULL, NULL)"
        do_sql(sql)
    seq = 1
    typelist = ['hostname', 'snmp_community', 'snmp_username', 'snmp_password', \
        'snmp_auth_protocol', 'snmp_priv_passphrase', 'snmp_priv_protocol', 'snmp_port', \
        'snmp_timeout', 'snmp_version']
    for input in str(options.script).split('<')[1::]:
        input = input.split('>')[0]
        if input == 'path_cacti':
            continue
        elif input in typelist:
            type = "'%s'" % (input)
        else:
            type = 'NULL'
        hash = gen_hash('data_input_fields')
        sql = "INSERT INTO data_input_fields VALUES (0, '%s', %s, '%s', '%s', " % \
            (hash, dim_id, input, input)
        sql += "'in', NULL, %s, %s, NULL, NULL)" % (seq, type)
        seq += 1
        do_sql(sql)
    print "Data Input Method created:"
    print "https://%s/cacti/data_input.php?action=edit&id=%s" % (options.wwwhost, dim_id)
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return dim_id

def create_data():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    for group in str(options.group).split('!'):
        if group == 'None': continue
        group = group.split(',')
        print "Running create_templates for %s" % (group)
        create_templates(dim_id, ds_list, group)
    for ds in ds_list:
        group = str(options.group)
        # No individual data and graph templates for already handled data sources.
        if group.startswith("%s," % (ds)) or ",%s!" % (ds) in group or \
            "!%s," % (ds) in group or ",%s," % (ds) in group or group.endswith(",%s" % (ds)):
            continue
        else:
            print "Running create_templates for %s" % (ds)
            create_templates(dim_id, ds_list, [ds])

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")


def create_templates(dim_id, full_ds_list, ds_list):
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    if options.title:
        name = options.title
    else:
        name = str(options.script).split()[0].split('/')[-1].split('\\')[-1].split('.')[0]
    if len(ds_list) > 1:
        name = "%s/" % (name)
        for item in ds_list:
            name += "%s," % (item)
        name = name[:-1]
    else:
        name = "%s/%s" % (name, ds_list[0])
    
    # Create Data Template first.
    hash = gen_hash('data_template')
    print "Creating Data Template '%s'" % (name)
    sql = "INSERT INTO data_template VALUES (0, '%s', '%s')" % \
        (hash, name)
    do_sql(sql)
    sql = "SELECT id FROM data_template WHERE hash='%s'" % (hash)
    dt_id = do_sql(sql)[0][0]
    sql = "INSERT INTO data_template_data VALUES (0, 0, 0, %s, %s, '', " % \
        (dt_id, dim_id)
    sql += "'|host_description| - %s', '', NULL, '', 'on', '', 300, '')" % (name)
    do_sql(sql)
    sql = "SELECT id FROM data_template_data WHERE local_data_template_data_id=0 AND "
    sql += "local_data_id=0 AND name='|host_description| - %s'" % (name)
    dtd_id = do_sql(sql)[0][0]
    for rra in [1, 2, 3, 4]:
        sql = "INSERT INTO data_template_data_rra VALUES (%s, %s)" % (dtd_id, rra)
        do_sql(sql)

    dstype_list = ['gauge', 'counter', 'derive', 'absolute']
    for ds in ds_list:
        dstype = options.dstype
        if options.dstypeoverride:
            override = options.dstypeoverride
            if override.startswith("%s:" % (ds)) or ",%s:" % (ds) in override:
                for over in override.split(','):
                    if over.startswith("%s:" % (ds)):
                        try:
                            dstype = dstype_list.index(over.split(':')[1].lower()) + 1
                        except:
                            print "Error in DS type override, don't know '%s'" % (over.split(':')[1])
                        continue
        ds_hash = gen_hash('data_template_rrd')

        # Get data_input_fields.id
        sql = "SELECT id FROM data_input_fields WHERE data_name='%s' AND data_input_id=%s" % \
            (ds, dim_id)
        try:
            dif_id = do_sql(sql)[0][0]
        except:
            print "Error grabbing dif_id for %s.  Typo in --group or in --script?" % (ds)
            sys.exit(0)

        # Add DS to Data Template
        print "Adding Data Source '%s' to Data Template '%s'" % (ds, name)
        sql = "INSERT INTO data_template_rrd VALUES (0, '%s', 0, 0, %s, " % \
            (ds_hash, dt_id)
        sql += "'', %s, '', %s, '', %s, '', %s, '', '%s', '', %s)" % \
            (options.rrdmax, options.rrdmin, options.rrdbeat, dstype, ds, dif_id)
        do_sql(sql)
    print "https://%s/cacti/data_templates.php?action=template_edit&id=%s" % \
        (options.wwwhost, dt_id)
        
    # Now Create Graph Template
    hash = gen_hash('graph_templates')
    print "Creating Graph Template '%s'" % (name)
    sql = "INSERT INTO graph_templates VALUES (0, '%s', '%s')" % \
        (hash, name)
    do_sql(sql)
    sql = "SELECT id FROM graph_templates WHERE hash='%s'" % (hash)
    gt_id = do_sql(sql)[0][0]
    sql = "INSERT INTO graph_templates_graph VALUES (0, 0, 0, %s, '', 1, " % (gt_id)
    sql += "'', '|host_description| - %s', '', '', %s, '', %s, '', 100, '', 0, '', '', " % \
        (name, options.height, options.width)
    sql += "'', 'on', '', 'on', '', 2, "
    sql += "'', " * 7
    sql += "'on', '', 1000, '0', '', '', 'on', '', '', '', '')"
    do_sql(sql)
    # And now create graph items
    num_colors = int(do_sql('''SELECT count(*) from colors''')[0][0]) - 1
    sequence = 1
    for ds in ds_list:
        dsn = ds[:19] # 19 character limit!
        hash = gen_hash('graph_templates_item')
        sql = "SELECT id FROM data_template_rrd WHERE data_template_id=%s AND data_source_name='%s'" % \
            (dt_id, dsn)
        ti_id = do_sql(sql)[0][0]
        color_id = int(do_sql("SELECT id FROM colors WHERE hex != 'FFFFFF' ORDER BY hex DESC LIMIT %i,1" % \
            ((num_colors/len(full_ds_list)) * full_ds_list.index(ds)))[0][0])
        if (options.area and sequence == 1): graph_type_id = 7
        if (options.area and sequence != 1): graph_type_id = 8
        if (not options.area): graph_type_id = 4
        # Line, Area, etc
        sql = "INSERT INTO graph_templates_item VALUES (0, '%s', 0, 0, %s, %s, " % \
            (hash, gt_id, ti_id)
        sql += "%s, 'FF', %s, 0, 1, '%s', '', '', 2, %s)" % \
            (color_id, graph_type_id, friendly_dict[ds], sequence)
        do_sql(sql)
 
        input_hash = gen_hash('graph_template_input')
        sql = "INSERT INTO graph_template_input VALUES (0, '%s', %s, " % \
            (input_hash, gt_id)
        sql += "'Data Source [%s]', NULL, 'task_item_id')" % (ds)
        do_sql(sql)
        sql = "SELECT id FROM graph_template_input WHERE hash='%s'" % (input_hash)
        input_id = do_sql(sql)[0][0]

        sql = "SELECT id FROM graph_templates_item WHERE hash='%s'" % (hash)
        item_id = do_sql(sql)[0][0]
        sql = "INSERT INTO graph_template_input_defs VALUES (%s, %s)" % \
            (input_id, item_id)
        do_sql(sql)

        sequence += 1
        # Current!
        hash = gen_hash('graph_templates_item')
        sql = "INSERT INTO graph_templates_item VALUES (0, '%s', 0, 0, %s, %s, " % \
            (hash, gt_id, ti_id)
        sql += "0, 'FF', 9, 0, 4, 'Current:', '', '', 2, %s)" % (sequence)
        do_sql(sql)

        sql = "SELECT id FROM graph_templates_item WHERE hash='%s'" % (hash)
        item_id = do_sql(sql)[0][0]
        sql = "INSERT INTO graph_template_input_defs VALUES (%s, %s)" % \
            (input_id, item_id)
        do_sql(sql)

        sequence += 1
        # Average
        hash = gen_hash('graph_templates_item')
        sql = "INSERT INTO graph_templates_item VALUES (0, '%s', 0, 0, %s, %s, " % \
            (hash, gt_id, ti_id)
        sql += "0, 'ff', 9, 0, 1, 'Average:', '', '', 2, %s)" % (sequence)
        do_sql(sql)

        sql = "SELECT id FROM graph_templates_item WHERE hash='%s'" % (hash)
        item_id = do_sql(sql)[0][0]
        sql = "INSERT INTO graph_template_input_defs VALUES (%s, %s)" % \
            (input_id, item_id)
        do_sql(sql)

        sequence += 1
        # Maximum
        hash = gen_hash('graph_templates_item')
        sql = "INSERT INTO graph_templates_item VALUES (0, '%s', 0, 0, %s, %s, " % \
            (hash, gt_id, ti_id)
        sql += "0, 'ff', 9, 0, 3, 'Maximum:', '', 'on', 2, %s)" % (sequence)
        do_sql(sql)

        sql = "SELECT id FROM graph_templates_item WHERE hash='%s'" % (hash)
        item_id = do_sql(sql)[0][0]
        sql = "INSERT INTO graph_template_input_defs VALUES (%s, %s)" % \
            (input_id, item_id)
        do_sql(sql)

        sequence += 1
    print "https://%s/cacti/graph_templates.php?action=template_edit&id=%s" % \
        (options.wwwhost, gt_id)
    cacti_cli = "/data/cacti/cli"
    if options.templates:
        for template in str(options.templates).split(','):
            try:
                ht_id = do_sql("SELECT id FROM host_template WHERE name='%s'" % \
                    (template))[0][0]
            except:
                print "No Templates found, named '%s'" % (template)
                continue
            do_sql("INSERT INTO host_template_graph VALUES (%s, %s)" % \
                (ht_id, gt_id))
    else:
        host_id = do_sql("SELECT id FROM host WHERE hostname='%s'" % (options.hostname))[0][0]
        do_sql("INSERT INTO host_graph VALUES (%s, %s)" % (host_id, gt_id))
        add_graph = "%s/add_graphs.php --graph-type=cg --graph-template-id=%s " % \
            (cacti_cli, gt_id)
        add_graph += "--host-id=%s" % (host_id)
        output = os.popen(add_graph).read()
        print output
        
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")

options = init()
(ds_list, friendly_dict) = run_script()
if options.justrun:
    print "Exiting."
    sys.exit(0)

dim_id = create_dim()
create_data()
sys.exit(0)

