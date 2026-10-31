#!/usr/bin/env python3
"""Include license/notice texts of the actual linked Go modules in a node package."""
import json
import os
from pathlib import Path
import subprocess
import sys

root=Path(__file__).resolve().parents[1]
go=os.environ.get('PANEL_GO',str(root.parent/'mobile/scripts/go.sh'))
raw=subprocess.check_output([go,'list','-deps','-json','./cmd/panel-server-node'],cwd=root/'engine/xray',env=dict(os.environ,GOWORK='off'))
text=raw.decode(); decoder=json.JSONDecoder();modules={}
while text.strip():
    text=text.lstrip();item,end=decoder.raw_decode(text);text=text[end:]
    module=item.get('Module')
    if module and module.get('Path')!='salfetka/panel/engine/xray':
        modules[module['Path']]=module.get('Replace',module).get('Dir')
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
index=[]
for name,directory in sorted(modules.items()):
    if name=='salfetka/panel':continue
    if not directory: raise RuntimeError('dependency_directory_missing')
    source=Path(directory)
    paths=[p for p in source.iterdir() if p.is_file() and p.name.lower().startswith(('license','copying','notice','copyright'))]
    if not paths: raise RuntimeError('dependency_license_missing:'+name)
    for p in paths:
        destination=name.replace('/','_')+'-'+p.name
        (out/destination).write_bytes(p.read_bytes())
        index.append({'module':name,'file':destination})
(out/'linked-modules.json').write_text(json.dumps(index,indent=2)+'\n')
