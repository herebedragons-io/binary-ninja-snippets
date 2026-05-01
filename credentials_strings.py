#
#
"""
Scans the binary for credentials-related strings.
Highlights and tags the functions they are found in.
"""

search_keywords = [
    "password",
    "pwd",
    "passwd",
    "credential",
    "cred",
    "pw",
    "apikey",
    "token",
  ]


log_info("Scanning for credentials-related strings...")

for search_str in search_keywords:
  log_info(f"Searching for string '{search_str}'.")

  # Search all strings
  log_info("### STRINGS ###")
  for str in bv.strings:
    if search_str.lower() in str.value.lower():
      log_info(f"Found string: \n{str.value} [{hex(str.start)}].")

  # Search all function names
  log_info("### FUNCTION NAMES ###")
  for func in bv.functions:
    if search_str.lower() in func.name.lower():
      log_info(f"Found function {func.name} [{hex(func.start)}].")

  # Search the linear view of the analyzed binary. This includes both the .data section 
  # where the string is declared and the .text section where it is used.
  log_info("### LINEAR VIEW ###")
  results = bv.find_all_text(bv.start, bv.end, search_str)
  for res in results:
    funcs = bv.get_functions_containing(res[0])
    if len(funcs) > 0:
      for func in funcs:
        log_info(f"Found disassembled line [{res[0]}]: {res[2]}")
        log_info(f"referenced by function {func.name} [{func.start}].")        
    else:
      log_info(f"Found disassembled line [{res[0]}]: {res[2]}")

log_info("Scanning for credentials-related strings complete.")
