#!/usr/bin/env python
# Grabs a set of data based on data template, host template, and data source name, then builds
# or updates an aggregate graph.
# Michael Lindsey <mike@5dninja.net>
# 12/1/2008

# -*- coding: ascii -*-

import base64
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
    default['height'] = 250
    default['width'] = 650
    default['cf'] = 'average'
    default['orderby'] = 'datasource'
    # collect option information, display help text if needed, set up debugging
    usage = "usage: %prog [options]\n"
    usage += "example: %prog -H ip-corpus-dbs -D 'FreeBSD - Memory' -S fBSDmemfree\n"
    usage += "example: %prog -H 'ip-corpus-dbs,ip-corpus-dbm' -D 'FreeBSD - Memory,Host MIB - Processes' -S 'fBSDmemfree,fBSDmemactive!proc'"
    parser = OptionParser(usage=usage)
    parser.add_option("-H", "--host", type="string", dest="host",
                            help="Comma separated list of host templates to graph.")
    parser.add_option("-D", "--data", type="string", dest="data",
                            help="Comma seperated list of data templates to graph.")
    parser.add_option("-S", "--source", type="string", dest="source",
                            help="Comma-seperated list of data sources inside rrd to use.  Defaults to first if not passed.  If multple data templates are passed, seperate the data source groups with !")
    parser.add_option("--dsfilter", type="string", dest="dsfilter",
                            help="Useful for aggregating individual disks or other multiple use graphs.")
    parser.add_option("--height", type="int", dest="height",
                            help="Height of aggregate graph. Default=%s" % (default['height']),
                            default=default['height'])
    parser.add_option("--width", type="int", dest="width",
                            help="Width of aggregate graph. Default=%s" % (default['width']),
                            default=default['width'])
    parser.add_option("--area", action="store_true", dest="area",
                            help="Create Area/Stack type graph instead of line type graph.  Subsequent data sources will be overlayed with increasing alpha transparencies.",
                            default=False)
    parser.add_option("--orderby", type="string", dest="orderby",
                            help="Order with which to sort graph items.  Options are: datasource, hostname.  Default=%s" % (default['orderby']),
                            default=default['orderby'])
    parser.add_option("--colorbyorder", action="store_true", dest="colorbyorder",
                            default=False,
                            help="Switch colors at orderby boundary instead of by data source.")
    parser.add_option("--label", type="string", dest="label",
                            help="Vertical Label", default="")
    parser.add_option("--title", type="string", dest="title",
                            help="Graph Title.  Will try to title with something vaugely appropriate if this option is missing.")
    parser.add_option("--includehosts", type="string", dest="includehosts",
                            help="Include only these hosts.  Use % for wildcards.")
    parser.add_option("--excludehosts", type="string", dest="excludehosts",
                            help="Exclude these hosts.  Use % for wildcards.  --includehosts is processed before --excludehosts.")
    parser.add_option("--cf", type="string", dest="cf",
                            help="Consolidation function to use for the graphical portion of the graph.  Default=%s" % (default['cf']),
                            default=default['cf'])
    parser.add_option("-n", "--name", type="string", dest="name",
                            help="Database hostname to connect to. Default=%s" % (default['host']),
                            default=default['host'])
    parser.add_option("-d", "--database", type="string", dest="db",
                            help="Database to connect to. Default=%s" % (default['db']),
                            default=default['db'])
    parser.add_option("-u", "--user", type="string", dest="user",
                            help="User to connect to as. Default=%s" % (default['user']),
                            default=default['user'])
    parser.add_option("-p", "--password", type="string", dest="password",
                            help="Password to connect with. Default=<redacted>",
                            default=default['password'])
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                            default=False,
                            help="print debug messages to stderr")
    parser.add_option("--delete", action="store_true", dest="delete",
                            default=False,
                            help="Delete a graph that matches the arguments passed.  Useful when you screw up and need to delete a graph you just made.")
    parser.add_option("--autoupdate", action="store_true", dest="autoupdate",
                            default=False,
                            help="Scan the database and update existing aggregate graphs.")
    global options
    (options, args) = parser.parse_args()
    if options.verbose: sys.stderr.write(">>DEBUG sys.argv[0] running in " +
                            "debug mode\n")
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    if options.autoupdate:
        spawn_kids()
        sys.exit(0)
    if not options.host and not options.data:
        parser.print_help()
        sys.exit(-1)
    if ((options.source) and (options.data.count(',') != options.source.count('!')) or (options.data.count(',') and not options.source)):
        if not options.source:
            sourcecount = 0
        else:
            sourcecount = options.source.count('!') + 1
        print "Mismatch in data template and data source grouping."
        print "%i data templates, and %i data source groups." % (options.data.count(',') + 1, sourcecount)
        options.source += (options.data.count(',') - options.source.count('!')) * '!Null'
        find_host_template()
        find_data_template()
        find_data_source()
        sys.exit(-1)
    if options.cf.lower() == 'average':
        options.cf = 1
    elif options.cf.lower() == 'minimum':
        options.cf = 2
    elif options.cf.lower() == 'maximum':
        options.cf = 3
    else:
        print "CF must be one of: average, minimum, maximum"
        sys.exit(-1)
    if options.includehosts:
        if (options.includehosts.count(';') or options.includehosts.count('"') or options.includehosts.count("'")):
            print "--includehosts MUST not contain ;, ', or \""
            sys.exit(-1)
    if options.excludehosts:
        if (options.excludehosts.count(';') or options.excludehosts.count('"') or options.excludehosts.count("'")):
            print "--excludehosts MUST not contain ;, ', or \""
            sys.exit(-1)
    options.orderby = options.orderby.lower()
    if (options.orderby != 'datasource' and options.orderby != 'hostname'):
            print "Invalid option for --orderby"
            parser.print_help()
            sys.exit(-1)
    options.label = options.label.replace(':','')
           

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return options

def init_db():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    conn = MySQLdb.connect (host = options.name,
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

def find_host_template():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    host_templates = list(do_sql('select name from host_template'))
    for template in options.host.split(','):
        if not host_templates.count((template,)):
            print "Host template '%s' not in cacti database." % (template)
            print "Valid templates are:"
            for template in sorted(host_templates): print "'%s'" % (template[0])
            print "Please fix your error and try again."
            sys.exit(-1)
        print "Found host template %s." % (template)
   

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")

def find_data_template():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    for host in options.host.split(','):
        for data in options.data.split(','):
            data_templates = list(do_sql('''SELECT data_local.id
                FROM data_local, host, host_template, data_template
                WHERE data_local.host_id=host.id
                AND host.host_template_id=host_template.id
                AND data_local.data_template_id=data_template.id
                AND host_template.name='%s'
                AND data_template.name='%s'
                GROUP BY data_local.id''' % (host, data)))
            if (len(data_templates) == 0):
                print "No matches for the combination of host template '%s' and data template '%s'." % (host, data)
                data_templates = list(do_sql('''SELECT data_template.name
                    FROM data_local, host, host_template, data_template
                    WHERE data_local.host_id=host.id
                    AND host.host_template_id=host_template.id
                    AND data_local.data_template_id=data_template.id
                    AND host_template.name='%s'
                    GROUP BY data_template.name''' % (host)))
                print "Valid data templates for that host template are:"
                for template in data_templates: print "'%s'" % (template[0])
                print "Please fix your error and try again."
                sys.exit(-1)
        
        print "Found data template %s/%s." % (host, data)

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")

def find_data_source():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    x = -1
    for data in options.data.split(','):
        x += 1
        data_source_names = []
        for host in options.host.split(','):
            dsn = do_sql('''SELECT data_template_rrd.data_source_name
                FROM data_template_rrd, data_template, data_local, host, host_template 
                WHERE data_template_rrd.data_template_id=data_template.id
                AND data_template_rrd.local_data_id=data_local.id
                AND data_local.host_id=host.id
                AND host.host_template_id=host_template.id
                AND host_template.name='%s'
                AND data_template.name='%s'
                GROUP BY data_template_rrd.data_source_name''' % (host, data))
            for ds in dsn: data_source_names.append(ds[0])
            if options.source:
                for source in options.source.split('!')[x].split(','):
                    if (source not in data_source_names):
                        print "Data Source '%s/%s/%s' not found in cacti database." % (host, data, source)
                        print "Valid DS options for your data template are:"
                        for ds in sorted(data_source_names): print "'%s'" % (ds)
                        print "Please fix your error and try again."
                        sys.exit(-1)
                    print "Found data source '%s/%s/%s'." % (host, data, source)
            else:
                print "No Source passed, using '%s'..  Hopefully this is ok." % (data_source_names[0])
                options.source = data_source_names[0]


    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")

def get_task_items():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    task_items = []
    host_sql = 'AND ('
    for host in options.host.split(','):
        host_sql += 'host_template.name="%s" OR ' % (host)
    host_sql = host_sql[0:-3] + ')'
    data_sql = 'AND ('
    for data in options.data.split(','):
        data_sql += 'data_template.name="%s" OR ' % (data)
    data_sql = data_sql[0:-3] + ')'
    source_sql = 'AND ('
    for group in options.source.split('!'):
        for source in group.split(','):
            source_sql += 'data_template_rrd.data_source_name="%s" OR ' % (source)
    source_sql = source_sql[0:-3] + ')'

    dsfilter = ''
    if options.dsfilter:
        dsfilter = "AND data_template_data.name_cache LIKE '%%%s%%'" % (options.dsfilter)
    incexchosts = ''
    if options.includehosts:
        incexchosts += 'AND host.hostname LIKE "%s" ' % (options.includehosts)
    if options.excludehosts:
        incexchosts += 'AND host.hostname NOT LIKE "%s" ' % (options.excludehosts)
    if (options.orderby == 'hostname'):
        order_sql = 'ORDER BY host.hostname, data_template_rrd.data_source_name'
    else:
        order_sql = 'ORDER BY data_template_rrd.data_source_name, host.hostname'
    items = list(do_sql('''SELECT data_template_rrd.id
        FROM data_template_rrd, data_template, data_local, host, host_template, data_template_data
        WHERE data_template_rrd.data_template_id=data_template.id
        AND data_template_rrd.local_data_id=data_local.id
        AND data_local.host_id=host.id
        AND host.host_template_id=host_template.id
	AND data_local.id=data_template_data.local_data_id
        %s
        %s
        %s
        %s
        %s
	GROUP BY data_template_data.name_cache, data_template_rrd.data_source_name
        %s''' % (host_sql, data_sql, source_sql, dsfilter, incexchosts, order_sql)))
    for item in items: task_items.append(item[0])
    if (len(task_items) == 0):
        print "No task items found.  Please check that you are using a valid Host/Data"
        print "template combination and that your include/exclude options are correct."
        sys.exit(-1)
    if (len(task_items) == 1):
        print "Only one task item found, hopefully there will be more later."

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")
    return (task_items)

def spawn_kids():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    tml = do_sql("SELECT title FROM graph_templates_graph WHERE title LIKE 'A:%:%:%:%:%:%:%:%:%:%:%'")
    for meta in tml:
        meta = meta[0].split(':')
        host = meta[1]
        data = meta[2]
        source = meta[3]
        cf = meta[4]
        area = meta[5]
        orderby = meta[6]
        colorby = meta[7]
        include = meta[8]
        exclude = meta[9]
        label = meta[10]
        title = meta[11:]

        cmd = "%s -H '" % (sys.argv[0])
        for h in host.split(','):
            cmd += do_sql('SELECT name FROM host_template WHERE id="%s"' % (h))[0][0] + ','
        cmd = "%s' -D '" % (cmd[:-1])
        for d in data.split(','):
            cmd += do_sql('SELECT name FROM data_template WHERE id="%s"' % (d))[0][0] + ','
        cmd = "%s'" % (cmd[:-1])
        if (len(source)):
            dsfilter = ''
            if source.count('^'):
                (source,dsfilter) = source.split('^')
                dsfilter = "--dsfilter '%s'" % (dsfilter)
            cmd = "%s -S '%s' %s" % (cmd, source, dsfilter)
        if cf == 1: cmd = "%s --cf average" % (cmd)
        if cf == 2: cmd = "%s --cf minimum" % (cmd)
        if cf == 3: cmd = "%s --cf maximum" % (cmd)
        if area == "T": cmd = "%s --area" % (cmd)
        if orderby == "d": cmd = "%s --orderby datasource" % (cmd)
        if orderby == "h": cmd = "%s --orderby hostname" % (cmd)
        if colorby == "T": cmd = "%s --colorbyorder" % (cmd)
        if len(include): cmd = "%s --includehosts '%s'" % (cmd, include)
        if len(exclude): cmd = "%s --excludehosts '%s'" % (cmd, exclude)
        if len(label): cmd = "%s --label '%s'" % (cmd, label)
        if len(title):
            fulltitle = ""
            for part in title:
                fulltitle = "%s%s:" % (fulltitle, part)
            cmd = "%s --title '%s'" % (cmd, fulltitle[:-1])
           
        for line in os.popen(cmd).readlines(): print line,
 
    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")


def create_graph():
    if options.verbose: sys.stderr.write(">>DEBUG start - " + funcname() + 
                            "()\n")
    hosttemplate_id = do_sql("SELECT id FROM host_template where name='%s'" % (options.host.replace(",","' OR name='")))
    temp = ''
    for template in hosttemplate_id: temp += '%s,' % (template[0])
    hosttemplate_id = temp[:-1]
    datatemplate_id = do_sql("SELECT id FROM data_template where name='%s'" % (options.data.replace(",","' OR name='")))
    temp = ''
    for template in datatemplate_id: temp += '%s,' % (template[0])
    datatemplate_id = temp[:-1]
    for template in datatemplate_id: temp += '%s,' % (template[0])
    total_cdef = do_sql("SELECT id FROM cdef where name='%s'" % ('Total All Data Sources'))[0]
    totalsimilar_cdef = do_sql("SELECT id FROM cdef where name='%s'" % ('Total Similar Data Sources'))[0]
    if (len(total_cdef) == 0):
        print "CDEF entry 'Total All Data Sources' not found.  Please fix and rerun."
    if (len(totalsimilar_cdef) ==0):
        print "CDEF entry 'Total Similar Data Sources' not found.  Please fix and rerun."
    if (len(total_cdef) == 0 or len(totalsimilar_cdef) ==0):
        sys.exit(-1)

    dsfilter = ''
    if options.dsfilter:
        dsfilter = '^%s' % (options.dsfilter)
    title_meta = 'A:%s:%s:%s%s:%s:%s:%s:%s' % (hosttemplate_id, datatemplate_id, options.source, dsfilter, options.cf, str(options.area)[0], str(options.orderby)[0], str(options.colorbyorder)[0])
    if options.includehosts:
        title_meta += ':%s' % (options.includehosts)
    else:
        title_meta += ':'
    if options.excludehosts:
        title_meta += ':%s' % (options.excludehosts)
    else:
        title_meta += ':'

    if not options.title:
        title_host = options.host.split('-')
        if (len(title_host) == 3):
            title_host = "%s %s" % (title_host[1].capitalize(), title_host[2].capitalize())
        elif (len(title_host) == 5):
            split = title_host[2].split(',')
            title_host = "%s %s,%s %s" % (title_host[1].capitalize(), split[0].capitalize(), title_host[3].capitalize(), title_host[4].capitalize())
        else:
            title_host = options.host
        title_source = ''
        for source in options.source.split(',')[0:2]:
            title_source += '%s,' % (source)
        title_host = "Aggr: %s/%s/%s" % (title_host, options.data, title_source[:-1])
        if (len(options.source.split(',')) > 2): title_host += '...'
    else:
        title_host = options.title
    results = do_sql('''SELECT local_graph_id
        FROM graph_templates_graph
        WHERE title like "%s:%%"''' % (title_meta))
    title_meta += ':%s:' % (options.label)
    if options.title: title_meta += '%s' % (options.title)

    if (len(results) == 0):
        graph_local = do_sql('''LOCK TABLE graph_local WRITE;
            INSERT INTO graph_local VALUES (NULL, 0, 0, 0, 0);
            SELECT max(id) FROM graph_local''')[0][0]
        print "Graph does not exist, creating with id #%s" % (graph_local)
        do_sql('''INSERT INTO graph_templates_graph (local_graph_id, title, title_cache, height, width, vertical_label, image_format_id, base_value)
            VALUES (%s, '%s', '%s', %s, %s, '%s', 1, 1000)''' % (graph_local, title_meta, title_host, options.height, options.width, options.label))
            
    else:
        graph_local=results[0][0]
        if options.delete:
            print "Deleting existing graph id #%s" % (graph_local)
            do_sql('''DELETE FROM graph_templates_item
                WHERE local_graph_id=%s''' % (graph_local))
            do_sql('''DELETE FROM graph_templates_graph WHERE local_graph_id=%s''' % (graph_local))
        else:
            print "Graph exists.  Updating with id #%s" % (graph_local)
            do_sql('''UPDATE graph_templates_graph SET title='%s' WHERE local_graph_id=%s''' % (title_meta, graph_local))
            if options.title:
                do_sql('''UPDATE graph_templates_graph SET title_cache='%s' WHERE local_graph_id=%s''' % (options.title, graph_local))
            else:
                do_sql('''UPDATE graph_templates_graph SET title_cache='%s' WHERE local_graph_id=%s''' % (title_host, graph_local))
            if options.label: do_sql('''UPDATE graph_templates_graph SET vertical_label='%s' WHERE local_graph_id=%s''' % (options.label, graph_local))
            do_sql('''DELETE FROM graph_templates_item
                WHERE local_graph_id=%s''' % (graph_local))

    sequence = 0
    item_num = 1
    old_source = ''
    old_host = ''
    old_item = ''
    num_colors = int(do_sql('''SELECT count(*) from colors''')[0][0]) - 1
    alpha = 'ff'
    for item in task_items:
        source = str(do_sql('''SELECT data_source_name FROM
            data_template_rrd WHERE data_template_rrd.id=%s''' % (item))[0][0])
        host = str(do_sql('''SELECT host.hostname
            FROM host, data_local, data_template_rrd
            WHERE host.id=data_local.host_id
            AND data_template_rrd.local_data_id=data_local.id
            AND data_template_rrd.id=%s''' % (item))[0][0])
        
        if (((source != old_source) and options.orderby == 'datasource') or ((host != old_host) and options.orderby == 'hostname')):
            first = 1
            if (sequence > 0):
                if (options.area): alpha = '50'
                if options.orderby =='datasource':
                    do_sql('''INSERT INTO graph_templates_item (local_graph_id, task_item_id, graph_type_id, cdef_id, consolidation_function_id, text_format, sequence, gprint_id, hard_return)
                        VALUES (%s, %s, 9, %s, 1, ' Average Total %s:', %s, 2, 'on')''' % (graph_local, old_item, totalsimilar_cdef[0], old_source, sequence))
                    sequence += 1
        else:
            first = 0
        if (options.area and first == 1): graph_type_id = 7
        if (options.area and first != 1): graph_type_id = 8
        if (not options.area): graph_type_id = 4
        if ((options.colorbyorder and first == 1) or not options.colorbyorder): 
            color_id = int(do_sql('''SELECT id FROM colors ORDER BY hex DESC LIMIT %i,1''' % ((num_colors/len(task_items)) * item_num))[0][0])
        text_format = str(do_sql('''SELECT data_template_data.name_cache
            FROM data_template_data, data_template_rrd
            WHERE data_template_data.local_data_id=data_template_rrd.local_data_id
            AND data_template_rrd.id=%s
            AND data_template_rrd.data_source_name="%s"''' % (item, source))[0][0]) + ":" + source
        first = 2
        do_sql('''INSERT INTO graph_templates_item (local_graph_id, task_item_id, color_id, graph_type_id, consolidation_function_id, text_format, sequence, hard_return, alpha)
            VALUES (%s, %s, %s, %s, %s, "%s", %s, 'on', '%s')''' % (graph_local, item, color_id, graph_type_id, options.cf, text_format, sequence, alpha))
        sequence += 1
        do_sql('''INSERT INTO graph_templates_item (local_graph_id, task_item_id, graph_type_id, consolidation_function_id, text_format, sequence, gprint_id)
            VALUES (%s, %s, 9, 4, ' Current:', %s, 2)''' % (graph_local, item, sequence))
        sequence += 1
        do_sql('''INSERT INTO graph_templates_item (local_graph_id, task_item_id, graph_type_id, consolidation_function_id, text_format, sequence, gprint_id)
            VALUES (%s, %s, 9, 1, 'Average:', %s, 2)''' % (graph_local, item, sequence))
        sequence += 1
        do_sql('''INSERT INTO graph_templates_item (local_graph_id, task_item_id, graph_type_id, consolidation_function_id, text_format, sequence, gprint_id, hard_return)
            VALUES (%s, %s, 9, 3, 'Maximum:', %s, 2, 'on')''' % (graph_local, item, sequence))
        sequence += 1
        item_num += 1
        old_source = source
        old_host = host 
        old_item = item
    if options.orderby =='datasource':
        do_sql('''INSERT INTO graph_templates_item (local_graph_id, task_item_id, graph_type_id, cdef_id, consolidation_function_id, text_format, sequence, gprint_id, hard_return)
            VALUES (%s, %s, 9, %s, 1, ' Average Total %s:', %s, 2, 'on')''' % (graph_local, item, totalsimilar_cdef[0], source, sequence))
        sequence += 1
    do_sql('''INSERT INTO graph_templates_item (local_graph_id, task_item_id, graph_type_id, cdef_id, consolidation_function_id, text_format, sequence, gprint_id, hard_return)
        VALUES (%s, %s, 9, %s, 1, ' Full Total:', %s, 2, 'on')''' % (graph_local, item, total_cdef[0], sequence))

    print "https://cacti-www1.soma.ironport.com/cacti/graph.php?action=view&local_graph_id=%s&rra_id=all" % (graph_local)

    if options.verbose: sys.stderr.write(">>DEBUG end    - " + funcname() + 
                            "()\n")

options = init()

find_host_template()
find_data_template()
find_data_source()

task_items = get_task_items()

create_graph()

sys.exit(0)

