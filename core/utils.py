
import importlib
import scanners
import inspect

def add_underscores(s : str):
    r = ""
    for u, l in zip(s,s.lower()):
        r += l if u==l else "_"+l
    if r.endswith("_scanner"):
        r = r[:-8]
    return r[1:]

def get_scanner_categories():

    scan_types = ["prompt", "chain", "output"]

    categories = {}
    for scan in scan_types:
        module = importlib.import_module("scanners."+scan)
        names = module.__all__
        scanners = {}

        for n in names:
            if "Scanner" in n:
                _class = getattr(module, n)
                scan_name = add_underscores(_class.__name__)
                scanners[scan_name] = {"class": _class,
                                         "description":_class.__doc__.strip().split("\n")[0]
                                         }
    
                params = {}
                sig = inspect.signature(_class.__init__).parameters
                args = sig.keys()
                for arg in args:
                    if arg != "self":
                        default = sig[arg].default
                        if default != inspect._empty:
                            params[arg] = default
                        else:
                            params[arg] = None
    
                if params:
                    scanners[scan_name]["params"] = params

        categories[scan] = {"description":module.__doc__.strip(), "scanners":scanners}

    return categories 

