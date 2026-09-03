import os
import re

def downgrade_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    original = content
    
    needs_optional = False
    needs_union = False
    
    # 1. Optional[str ] -> Optional[str]
    content, n1 = re.subn(r'([A-Za-z_][A-Za-z0-9_\[\], ]*)\s*\|\s*None', r'Optional[\1]', content)
    # 2. Optional[str ]-> Optional[str]
    content, n2 = re.subn(r'None\s*\|\s*([A-Za-z_][A-Za-z0-9_\[\], ]*)', r'Optional[\1]', content)
    
    if n1 > 0 or n2 > 0:
        needs_optional = True

    # 3. Union[Type1 , Type2 ]-> Union[Type1, Type2]
    # Union[Union[We loop to handle multiple unions like A , B ], C ]-> Union[Union[A, B], C]
    prev_content = ""
    while '|' in content and content != prev_content:
        prev_content = content
        # Union[We need to be careful not to match , inside strings or comments]. But for simple type hints it should be fine.
        # Let's target specific type hints we know are in this repo
        content, n3 = re.subn(r'([A-Za-z_][A-Za-z0-9_\[\], ]*)\s*\|\s*([A-Za-z_][A-Za-z0-9_\[\], ]*)', r'Union[\1, \2]', content)
        if n3 > 0:
            needs_union = True

    if needs_optional or needs_union:
        imports = []
        if needs_optional and 'Optional' not in content: imports.append('Optional')
        if needs_union and 'Union' not in content: imports.append('Union')
        if imports:
            import_stmt = f"from typing import {', '.join(imports)}\n"
            first_import = re.search(r'^import |^from ', content, flags=re.MULTILINE)
            if first_import:
                idx = first_import.start()
                content = content[:idx] + import_stmt + content[idx:]
            else:
                content = import_stmt + content

    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Downgraded types in {filepath}")

for root, _, files in os.walk('.'):
    if 'venv' in root: continue
    for file in files:
        if file.endswith('.py'):
            downgrade_file(os.path.join(root, file))
