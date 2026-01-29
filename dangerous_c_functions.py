"""
Scans function symbols in the binary.
Highlights and tags the usage of dangerous C functions.

Adapted from: https://www.youtube.com/watch?v=gLggUUy0-iI (@ConsoleCowboys)
"""

# Taken from Git's banned C functions: https://github.com/git/git/blob/master/banned.h
dangerous_functions = [
    "gets",
    "sprintf",
    "vsprintf",
    "strcat",
    "strncat",
    "strcpy",
    "strncpy",
    "strtok",
    "strtok_r",
    "gmtime",
    "localtime",
    "ctime",
    "ctime_r",
    "asctime",
    "asctime_r",
    "mktemp"
]

tag_type = bv.get_tag_type("Dangerous")
if tag_type is None:
    bv.create_tag_type("Dangerous", "☠️")

func_syms = bv.get_symbols_of_type(SymbolType.FunctionSymbol)
func_syms.extend(bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol))

log_info("Scanning for dangerous C functions...")

for sym in func_syms:
    if sym.name in dangerous_functions:
        func = bv.get_function_at(sym.address)
        if func is None:
            continue

        log_info(f"Dangerous C function {func.name} at address {hex(func.start)}")

        for xref in func.caller_sites:
            caller_func = xref.function
            caller_addr = xref.address

            # Highlight the caller instruction in red
            caller_func.set_user_instr_highlight(caller_addr, HighlightStandardColor.RedHighlightColor)

            # Tag the caller as well if it hasn't already been tagged
            tagged = False
            for tag in bv.get_tags_at(caller_addr, False):
                if tag.type.name == "Dangerous":
                    tagged = True
            
            if not tagged:
                bv.add_tag(caller_addr, "Dangerous", "Dangerous C Function", True)

log_info("Scanning for dangerous C functions completed.")