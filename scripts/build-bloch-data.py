"""Build public examples and a deterministic, dependency-free offline package."""
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

root = Path(__file__).resolve().parent.parent
site = root / 'apps/bloch-data'
script = '''
import {MODULES,defaultConfig} from './apps/bloch-data/assets/modules.v1.mjs';
import {samplesFor} from './apps/bloch-data/assets/samples.v1.mjs';
const result={};
for(const module of Object.keys(MODULES))for(const region of ['global','br']){
const config=defaultConfig(module,region);samplesFor(config).forEach((text,index)=>{result[`${module}-${region}-${index?'b':'a'}.csv`]=text;});}
console.log(JSON.stringify(result));
'''
fixtures = json.loads(subprocess.check_output(['node', '--input-type=module', '-e', script], cwd=root))
(site/'samples').mkdir(exist_ok=True)
for name, content in fixtures.items():
    (site/'samples'/name).write_text(content)
(site/'samples/venue.csv').write_text(fixtures['trades-global-a.csv'])
(site/'samples/clearing.csv').write_text(fixtures['trades-global-b.csv'])
(site/'downloads').mkdir(exist_ok=True)
package = site/'downloads/bloch-data-local-workbench-v2.zip'
files = [site/'index.html', site/'README.md', site/'GOVERNANCE.md', site/'regulatory-register.v1.json']
files += [site/'assets'/name for name in ['exchange.v2.css','modules.v1.mjs','reconcile.v1.mjs','samples.v1.mjs','workbench.v2.mjs','audit.v1.mjs','verification.v1.mjs','bloch-inc-logo-dark.png','favicon.png']]
files += sorted((site/'samples').glob('*.csv'))
with zipfile.ZipFile(package, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for file in files:
        data = file.read_bytes()
        if file.name == 'index.html':
            data = data.replace(b'href="downloads/bloch-data-local-workbench-v2.zip" download', b'href="README.md"')
            data = data.replace(b'Download the offline workbench', b'Offline instructions')
            data = data.replace(b'Download for your environment', b'Offline instructions')
        entry = zipfile.ZipInfo(str(file.relative_to(site)), date_time=(2026,9,24,0,0,0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = 0o644 << 16
        archive.writestr(entry, data)
digest = hashlib.sha256(package.read_bytes()).hexdigest()
package.with_suffix('.zip.sha256').write_text(f'{digest}  {package.name}\n')
print(f'{len(files)} files; {package.stat().st_size} bytes; SHA-256 {digest}')
