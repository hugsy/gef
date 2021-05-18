"""
This script is the server-side of the XML-RPC defined for gef for
IDA Pro.
It will spawn a threaded XMLRPC server from your current IDA session
making it possible for gef to interact with IDA.

To run from inside IDA:
- open IDA on your binary and press Alt-F7
- a popup "Run Script" will appear, simply enter the location of this
  script

If all went well, you will see something like
[+] Creating new thread for XMLRPC server: Thread-1
[+] Starting XMLRPC server: 0.0.0.0:1337
[+] Registered 10 functions.

which indicates that the server is running.

If you edit HOST/PORT, use `gef config` command to edit them

Ref:
- https://docs.python.org/2/library/simplexmlrpcserver.html
- https://pymotw.com/2/SimpleXMLRPCServer/

@_hugsy_
"""

from __future__ import print_function

from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer, list_public_methods

import inspect
import string
import threading
import types

import idautils, idc, idaapi


HOST, PORT = "0.0.0.0", 1337
DEBUG = True

_breakpoints = set()
_current_instruction_color = None
_current_instruction = 0

try:
  long        # Python 2
except NameError:
  long = int  # Python 3


def expose(f):
    "Decorator to set exposed flag on a function."
    f.exposed = True
    return f


def is_exposed(f):
    "Test whether another function should be publicly exposed."
    return getattr(f, 'exposed', False)


def ishex(s):
    return s.startswith("0x") or s.startswith("0X")


class IDAWrapper(object):
    """Class to wrap the various IDA modules. Makes them thread safe by
    enforcing they run in the main thread (which is required by IDA >= 7.2).
    Generators returned from the function are automatically wrapped with a
    thread-safe generator.
    This also provides a mapping from <=6.95 to the newer API.
    Modified from
    https://github.com/vrtadmin/FIRST-plugin-ida/blob/3a4287c4faa83127f8792bf2737be99edcb070e1/first_plugin_ida/first.py
    """
    api_map = {
        "AddBpt": idc.add_bpt,
        "DelBpt": idaapi.del_bpt,
        "GetBptEA": idc.get_bpt_ea,
        "GetBptQty": idc.get_bpt_qty,
        "GetColor": idc.get_color,
        "Jump": idc.jumpto,
        "MakeComm": lambda ea, comm: idc.set_cmt(ea, comm, 0),
        "MakeName": idc.set_name,
        "SetColor": idc.set_color,
    }

    def __getattribute__(self, name):
        bad = "dummy not found"
        v = bad
        if idaapi.IDA_SDK_VERSION >= 700 and name in IDAWrapper.api_map:
            v = IDAWrapper.api_map[name]

        if v is bad:
            v = getattr(idaapi, name, bad)
        if v is bad:
            v = getattr(idautils, name, bad)
        if v is bad:
            v = getattr(idc, name, bad)
        if v is bad:
            print("[!] Error: Cannot find API method {}".format(name))
            return None

        # Wrap callables
        if callable(v):
            def call_wrap(*args, **kwargs):
                # Need a mutable value to store result
                rv = [None]
                # Wrapper that binds the args
                def c():
                    rv[0] = v(*args, **kwargs)
                idaapi.execute_sync(c, idaapi.MFF_WRITE)
                if isinstance(rv[0], types.GeneratorType):
                    return IDAWrapper.gen_wrap(rv[0])
                return rv[0]
            return call_wrap

        return v

    @classmethod
    def gen_wrap(cls, generator):
        """Wrap the provided generator with a getter that executes `next`
        in the main thread.
        """

        # Need a mutable value to store result
        v = [None]

        def c():
            try:
                v[0] = next(generator)
            except StopIteration:
                v[0] = StopIteration

        while True:
            idaapi.execute_sync(c, idaapi.MFF_WRITE)
            if v[0] is StopIteration:
                return
            yield v[0]


api = IDAWrapper()


class Gef:
    """
    Top level class where exposed methods are declared.
    """

    def __init__(self, server, *args, **kwargs):
        self.server = server
        self._version = ("IDA Pro", str(idaapi.IDA_SDK_VERSION))
        return


    def _dispatch(self, method, params):
        """
        Plugin dispatcher
        """
        if DEBUG:
            print("Received '%s'" % method)

        func = getattr(self, method)
        if not is_exposed(func):
            raise NotImplementedError('Method "%s" is not exposed' % method)

        if DEBUG:
            print("Executing %s(%s)" % (method, params))
        return func(*params)


    def _listMethods(self):
        """
        Class method listing (required for introspection API).
        """
        m = []
        for x in list_public_methods(self):
            if x.startswith("_"): continue
            if not is_exposed( getattr(self, x) ): continue
            m.append(x)
        return m


    def _methodHelp(self, method):
        """
        Method help (required for introspection API).
        """
        f = getattr(self, method)
        return inspect.getdoc(f)

    @expose
    def version(self):
        """ version() => None
        Return a tuple containing the tool used and its version
        Example: ida version
        """
        return self._version

    @expose
    def shutdown(self):
        """ shutdown() => None
        Cleanly shutdown the XML-RPC service.
        Example: ida shutdown
        """
        self.server.server_close()
        print("[+] XMLRPC server stopped")
        setattr(self.server, "shutdown", True)
        return 0

    @expose
    def makecomm(self, address, comment):
        """ makecomm(int addr, string comment) => None
        Add a comment to the current IDB at the location `address`.
        Example: ida makecomm 0x40000 "Important call here!"
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return api.MakeComm(addr, comment)

    @expose
    def setcolor(self, address, color="0x005500"):
        """ setcolor(int addr [, int color]) => None
        Set the location pointed by `address` in the IDB colored with `color`.
        Example: ida setcolor 0x40000
        """
        addr = long(address, 16) if ishex(address) else long(address)
        color = long(color, 16) if ishex(color) else long(color)
        return api.SetColor(addr, CIC_ITEM, color)

    @expose
    def makename(self, address, name):
        """ makename(int addr, string name]) => None
        Set the location pointed by `address` with the name specified as argument.
        Example: ida makename 0x4049de __entry_point
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return api.MakeName(addr, name)

    @expose
    def jump(self, address):
        """ jump(int addr) => None
        Move the IDA EA pointer to the address pointed by `addr`.
        Example: ida jump 0x4049de
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return api.Jump(addr)

    def get_struct(self, name):
        for idx, sid, sname in api.Structs():
            if sname == name:
                return sid
        return None

    @expose
    def importstruct(self, name):
        """ importstruct(string name) => dict
        Import an IDA structure in GDB which can be used with the `pcustom`
        command.
        Example: ida importstruct struct_1
        """
        struct = self.get_struct(name)
        if struct is None:
            return {}
        return {
            name: [x for x in api.StructMembers(struct)]
        }

    @expose
    def importstructs(self):
        """ importstructs() => dict
        Import all structures from the current IDB into GDB, to be used with the `pcustom`
        command.
        Example: ida importstructs
        """
        structs = {}
        for _, _, name in api.Structs():
            structs.update(self.importstruct(name))
        return structs

    @expose
    def sync(self, offset, added, removed):
        """ sync(offset, added, removed) => None
        Synchronize debug info with gef. This is an internal function. It is
        not recommended using it from the command line.
        """
        global _breakpoints, _current_instruction, _current_instruction_color

        if _current_instruction > 0:
            api.SetColor(_current_instruction, CIC_ITEM, _current_instruction_color)

        base_addr = api.get_imagebase()
        pc = base_addr + int(offset, 16)
        _current_instruction = long(pc)
        _current_instruction_color = api.GetColor(_current_instruction, CIC_ITEM)
        api.SetColor(_current_instruction, CIC_ITEM, 0x00ff00)
        api.Jump(_current_instruction)

        cur_bps = {api.GetBptEA(n)-base_addr for n in range(api.GetBptQty())}
        ida_added = cur_bps - _breakpoints
        ida_removed = _breakpoints - cur_bps
        _breakpoints = cur_bps

        # update bps from gdb
        for bp in added:
            api.AddBpt(base_addr+bp)
            _breakpoints.add(bp)
        for bp in removed:
            if bp in _breakpoints:
                _breakpoints.remove(bp)
            api.DelBpt(base_addr+bp)

        return [tuple(ida_added), tuple(ida_removed)]


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def start_xmlrpc_server():
    """
    Initialize the XMLRPC thread.
    """
    print("[+] Starting XMLRPC server: {}:{}".format(HOST, PORT))
    server = SimpleXMLRPCServer((HOST, PORT),
                                requestHandler=RequestHandler,
                                logRequests=False,
                                allow_none=True)
    server.register_introspection_functions()
    server.register_instance( Gef(server) )
    print("[+] Registered {} functions.".format( len(server.system_listMethods()) ))
    while True:
        if hasattr(server, "shutdown") and server.shutdown==True:
            break
        server.handle_request()

    return


if __name__ == "__main__":
    t = threading.Thread(target=start_xmlrpc_server, args=())
    t.daemon = True
    print("[+] Creating new thread for XMLRPC server: {}".format(t.name))
    t.start()
