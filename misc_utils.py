import re

class settings:
    trace = True
    debug = False

def fix_name(fn):
    demangled = demangle_name(fn, INF_SHORT_DN) 
    if demangled:
        return demangled
    else:
        return fn

def cs_start_call_trace():
    global settings
    print("################### START ########################")
    while True:
        ea = get_reg_value("rip")
        if settings.trace:
            enable_tracing(TRACE_FUNC, 1)
        #skip external functions and wolfssl stuff we already recognized
        if get_segm_name(ea) == ".text" and not GetFunctionName(ea).startswith("wc_"):
            StepInto()
        else:
            if settings.trace:
                enable_tracing(TRACE_FUNC, 0)
            StepUntilRet()
            GetDebuggerEvent(WFNE_SUSP, -1)
            if settings.trace:
                enable_tracing(TRACE_FUNC, 1)
        
        if GetMnem(ea) == 'call' or GetMnem(ea) == 'retn':
            fn = GetFunctionName(ea)
            name = fix_name(fn)
            print("%s: 0x%016x: %s:\n\t\t%s" % (get_segm_name(ea), ea, name, GetDisasm(ea) ) )
        GetDebuggerEvent(WFNE_SUSP, -1)
        if check_bpt(ea) > 0 :
            if settings.trace:
                enable_tracing(TRACE_FUNC, 0)
            break
    print("################### END ########################")

def get_stack_trace(depth, addr=None, frame_sp=None):
    if addr or frame_sp:
        curr = addr
        sp = frame_sp
    else:
        sp = get_reg_value("rsp")
        curr = get_reg_value("rip")
    if (depth > 0):
        items = list(FuncItems(curr))
        
        if settings.debug:
            print("Function starts at 0x%016x" % items[0]) 
        #if stack frame was created already, subtract frame size
        #search first n func items for creation
        search_items = 8 if len(items) >= 8 else len(items)
            
        found = False
        for i in range(0, search_items):
            inst = GetDisasm(items[i])
            match = re.findall("sub\s+rsp, ([0-9A-F]+)h", inst)
            if match: 
                if curr > items[i]:
                    sp += int(match[0], 16)
                found = True
                break

        if found == False:
            print("Frame not found, sorry")
            return False

        if settings.debug:
            print("sp: 0x%016x" % sp) 
        ret = get_qword( sp )
        print("0x%016x : %s" % (ret, fix_name(GetFunctionName(ret)) ))
        get_stack_trace(depth-1, ret, sp+8)
        return True

    return False

def patch_bytes(ea, string):
    for c in string:
        patch_byte(ea, ord(c))
        ea+=1

