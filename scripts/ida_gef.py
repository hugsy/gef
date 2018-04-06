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

import threading
import string
import inspect

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
    def MakeComm(self, address, comment):
        """ MakeComm(int addr, string comment) => None
        Add a comment to the current IDB at the location `address`.
        Example: ida MakeComm 0x40000 "Important call here!"
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return idc.MakeComm(addr, comment)

    @expose
    def SetColor(self, address, color="0x005500"):
        """ SetColor(int addr [, int color]) => None
        Set the location pointed by `address` in the IDB colored with `color`.
        Example: ida SetColor 0x40000
        """
        addr = long(address, 16) if ishex(address) else long(address)
        color = long(color, 16) if ishex(color) else long(color)
        return idc.SetColor(addr, CIC_ITEM, color)

    @expose
    def MakeName(self, address, name):
        """ MakeName(int addr, string name]) => None
        Set the location pointed by `address` with the name specified as argument.
        Example: ida MakeName 0x4049de __entry_point
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return idc.MakeName(addr, name)

    @expose
    def Jump(self, address):
        """ Jump(int addr) => None
        Move the IDA EA pointer to the address pointed by `addr`.
        Example: ida Jump 0x4049de
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return idc.Jump(addr)

    def GetStructByName(self, name):
        for (struct_idx, struct_sid, struct_name) in Structs():
            if struct_name == name:
                return struct_sid
        return None

    @expose
    def ImportStruct(self, struct_name):
        """ ImportStruct(string name) => dict
        Import an IDA structure in GDB which can be used with the `pcustom`
        command.
        Example: ida ImportStruct struct_1
        """
        if self.GetStructByName(struct_name) is None:
            return {}
        res = {struct_name: [x for x in StructMembers(self.GetStructByName(struct_name))]}
        return res

    @expose
    def ImportStructs(self):
        """ ImportStructs() => dict
        Import all structures from the current IDB into GDB, to be used with the `pcustom`
        command.
        Example: ida ImportStructs
        """
        res = {}
        for s in Structs():
            res.update(self.ImportStruct(s[2]))
        return res

    @expose
    def Sync(self, offset, added, removed):
        """ Sync(offset, added, removed) => None
        Synchronize debug info with gef. This is an internal function. It is
        not recommended using it from the command line.
        """
        global _breakpoints, _current_instruction, _current_instruction_color

        if _current_instruction > 0:
            idc.SetColor(_current_instruction, CIC_ITEM, _current_instruction_color)

        base_addr = idaapi.get_imagebase()
        pc = base_addr + int(offset, 16)
        _current_instruction = long(pc)
        _current_instruction_color = GetColor(_current_instruction, CIC_ITEM)
        idc.SetColor(_current_instruction, CIC_ITEM, 0x00ff00)
        print("PC @ " + hex(_current_instruction).strip('L'))
        # post it to the ida main thread to prevent race conditions
        idaapi.execute_sync(lambda: idc.Jump(_current_instruction), idaapi.MFF_WRITE)

        cur_bps = set([ idc.GetBptEA(n)-base_addr for n in range(idc.GetBptQty()) ])
        ida_added = cur_bps - _breakpoints
        ida_removed = _breakpoints - cur_bps
        _breakpoints = cur_bps

        # update bp from gdb
        for bp in added:
            idc.AddBpt(base_addr+bp)
            _breakpoints.add(bp)
        for bp in removed:
            if bp in _breakpoints:
                _breakpoints.remove(bp)
            idc.DelBpt(base_addr+bp)

        return [list(ida_added), list(ida_removed)]


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def start_xmlrpc_server():
    """
    Initialize the XMLRPC thread
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
