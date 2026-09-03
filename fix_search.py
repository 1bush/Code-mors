with open(r'C:\Users\roven\Desktop\Code-mors-repo\index.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 'sr-meta' in line and 'sr-item' in line:
        lines[i] = "    return '<div class=\"sr-item\" onclick=\"goToMessage('+h.c.id+','+h.m.id+')\"><div class=\"sr-contact\">'+esc(h.c.name)+' \\u00b7 '+h.m.time+'</div><div class=\"sr-text\">'+(h.m.self?'\\u2605 ':'')+mk+'</div></div>';\n"
        print(f'Fixed line {i+1}')
        break

with open(r'C:\Users\roven\Desktop\Code-mors-repo\index.html', 'w', encoding='utf-8') as f:
    f.writelines(lines)
