#!c:\python\python.exe

'''
@author:  m0t

'''

#this parse a gml file and creates a script for idapython 
#which can be used to import PS block highlighting in IDA

import sys
sys.path.append(sys.argv[0].rsplit('/', 1)[0] + "/ps_api")

from gml import *
from psx import *

if len(sys.argv) < 2:
    sys.stderr.write("usage: ps_idapy_gen_colorize.py <file 1> [file 2] [...] > import_changes.py")
    sys.exit(1)
	
print "#generated by ps_idapy_gen_colorize.py"
#print "\nfrom idaapi import *"
print "from idc import *"
print "\n"

# step through the input files.
for input_file in sys.argv[1:]:
    graph_parser = gml_graph()

    try:
        graph_parser.parse_file(input_file)
    except psx, x:
        sys.stderr.write(x.__str__())
        sys.exit(1)

    # step through each node in the graph.
    for i in xrange(graph_parser.num_nodes()):
        node  = graph_parser.get_node(i)
        label = node.get_label_stripped()
        
	#extracts start:end from label
	#print label
        lines = label.split("\n")
	matches = re.search("^([a-f0-9]+)",lines[0])
        start = matches.groups()[0]
	matches = re.search("^([a-f0-9]+)", lines[-1])
	end = matches.groups()[0]
	#print start,end
	
	#get g_fill color
	color = re.sub("#", "0x", node.get_g_fill())
	#print color
	
	#do the little magic
	print "ea = 0x"+start
	print "while ea <= 0x"+end+" :"
	print "\tSetColor(ea,1,"+color+")"
	print "\tea+=ItemSize(ea)"
	print ""
		
