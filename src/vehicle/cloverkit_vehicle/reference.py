"""Offline, source-aware DTC reference; unknown codes never acquire guessed meanings."""
import json, re, sqlite3
from contextlib import closing
from pathlib import Path

DATA = Path(__file__).parent/'data'
CODE = re.compile(r'[PCBU][0-3][0-9A-F]{3}')

class Reference:
    def __init__(self, path=DATA/'codes.sqlite3'): self.path=Path(path)

    def query(self, text='', make='', limit=40):
        limit=max(1,min(int(limit),100));text=str(text).strip()[:100];make=str(make).strip().upper()[:80]
        with closing(sqlite3.connect(f'file:{self.path.as_posix()}?mode=ro',uri=True)) as db:
            db.row_factory=sqlite3.Row
            exact=CODE.fullmatch(text.upper())
            where='code=?' if exact else '(code LIKE ? OR title LIKE ?)'
            params=[text.upper()] if exact else ['%'+text.upper()+'%','%'+text+'%']
            # Manufacturer text is shown only with matching manufacturer context.
            where+=' AND make IN (?,?)';params += ['GENERIC',make or 'GENERIC']
            rows=db.execute('SELECT * FROM definitions WHERE '+where+' ORDER BY make DESC,code,source LIMIT ?',params+[limit]).fetchall()
        return [dict(row, detail=json.loads(row['detail'])) for row in rows]

    def describe(self,code,make=''):
        code=str(code).upper()
        rows=self.query(code,make,20) if CODE.fullmatch(code) else []
        preferred=next((r for r in rows if r['make']==make.upper()),None) or next((r for r in rows if r['source']=='obdex'),None) or (rows[0] if rows else None)
        return dict(code=code,description=preferred['title'] if preferred else 'Unknown / manufacturer-specific definition not available',
                    definitions=rows,conflicting_definitions=len({r['title'].casefold() for r in rows})>1,
                    caution='A code describes a detected condition; it does not prove a part needs replacing.')

    def catalog(self): return json.loads((self.path.parent/'provenance.json').read_text())

def advice(entry):
    """Show sourced possibilities, not upstream cost/likelihood/safe-to-drive predictions."""
    detail=entry.get('detail',{})
    causes=[c.get('label',{}).get('en','') for c in detail.get('common_causes',[]) if isinstance(c,dict)]
    return dict(explanation=detail.get('description',{}).get('en',''),possible_causes=[c for c in causes if c],
                next_checks=['Save codes and freeze frames before clearing.',
                             'Compare related readings and wiring with the applicable service information.',
                             'Confirm the cause with testing before replacing components.'],
                sources=detail.get('sources',[]))
