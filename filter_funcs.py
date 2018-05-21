#find relevant functions
#names = [ [name, addr], ..]

def cs_get_all_function_names():
    names=[]
    for f in Functions():
        fn = GetFunctionName(f)
        demangled = demangle_name(fn, INF_SHORT_DN)
        if demangled:
            name = demangled
        else:
            name = fn
        #skip jumpers
        if not fn.startswith("j_?"): 
            names.append([name, f])

    names.sort()
    return names

def cs_remove_std(names):
    for name in names:
        if name[0].startswith("std::") or name[0].startswith("public: std::") or \
                name[0].startswith("protected: std::") or \
                name[0].startswith("private: std::"):
            names.remove(name)
    return names

def cs_filter_functions(names, filter_str):
    filtered = []
    for name in names:
        if name[0].find(filter_str) >= 0:
            filtered.append(name)
    return filtered

def cs_breakpoint_all(names):
    count = 0
    for n in names:
        add_bpt(n[1])
        count += 1
    print("Set %d new breakpoints" % count)

def cs_breakpoint_remove(names):
    count = 0
    for n in names:
        del_bpt(n[1])
        count += 1
    print("Removed %d breakpoints" % count)

def cs_print_functions(names):
    print("################### START ########################")
    
    for name in names:
        
            print("0x%016x: %s" % ( name[1], name[0] ))

    print("Count: %d items" % len(names))

    print("################### END ########################")