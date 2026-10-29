"""CloverKit offline vehicle diagnostics. Hardware coverage is discovered, never assumed."""
__version__ = '0.1.1'

def subprocess_environment():
    import os
    from pathlib import Path
    base=Path(__file__).resolve().parent.parent
    env=os.environ.copy();env['PYTHONPATH']=os.pathsep.join([str(base),str(base/'vendor')]+([env['PYTHONPATH']] if env.get('PYTHONPATH') else []))
    return env
