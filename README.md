# Chrome Local Storage

Chromium based browsers local storage parser with no dependencies.

Code taken from here and slightly modified: https://github.com/cclgroupltd/ccl_chromium_reader

### Usage:
```python
from os import getenv
from pathlib import Path 
from ccl.ccl_chromium_localstorage import LocalStoreDb

leveldb = Path(getenv('LOCALAPPDATA')) / 'Google' / 'Chrome' / 'User Data' / 'Default' / 'Local Storage' / 'leveldb'
if leveldb.exists():
    
    db = LocalStoreDb(leveldb)
    
    for rec in db.iter_all_records():
        batch = db.find_batch(rec.leveldb_seq_number)
        print(rec, batch)

```

