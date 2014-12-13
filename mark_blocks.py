'''
@author:  m0t

'''

#search for blocks colored purple(0x9933cc) and creates a disabled breakpoint at the start of each.
#To be used with process stalker to immediately see "interesting" blocks

from idc import *
from idautils import *

purple = 0x9933cc	#our definition of purple...

#get start address of each function, scan it for purple, setbreakpoint()
funit = Functions()
prevFlag = False
while True:
	try:
		faddr = funit.next()
	except StopIteration:
		break
	itemsit = FuncItems(faddr)
	while True:
		try:
			item = itemsit.next()
		except StopIteration:
			break
		if GetColor(item, 1) == purple and prevFlag == False:
			AddBpt(item)
			EnableBpt(item, False)
			prevFlag = True
		#resetting the flag when we go out of "interesting" block
		if GetColor(item, 1) != purple and prevFlag == True:
			prevFlag = False

