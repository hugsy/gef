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
import random

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


"""
Wrappers taken from FIRST IDA Plugin
https://github.com/vrtadmin/FIRST-plugin-ida/blob/dev/first_plugin_ida/first.py
On IDA > 7.2  some functions are thread-safe and need to be executed on the
main Thread.
The function idaapi.execute_sync is called to execute these functions.
"""
class IDAWrapper(object):
    '''
    Class to wrap functions that are not thread safe.  These functions must
    be run on the main thread to avoid random crashes (and starting in 7.2,
    this is enforced by IDA, with an exception being generated if a
    thread-unsafe function is called from outside of the main thread.)
    '''
    mapping = {
        'get_tform_type' : 'get_widget_type',
    }
    def __init__(self):
        self.version = idaapi.IDA_SDK_VERSION

    def __getattribute__(self, name):
        default = '[1st] default'

        if (idaapi.IDA_SDK_VERSION >= 700) and (name in IDAWrapper.mapping):
            name = IDAWrapper.mapping[name]

        val = getattr(idaapi, name, default)
        if val == default:
            val = getattr(idautils, name, default)

        if val == default:
            val = getattr(idc, name, default)

        if val == default:
            msg = 'Unable to find {}'.format(name)
            idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))
            return

        if hasattr(val, '__call__'):
            def call(*args, **kwargs):
                holder = [None] # need a holder, because 'global' sucks

                def trampoline():
                    holder[0] = val(*args, **kwargs)
                    return 1

                # Execute the request using MFF_WRITE, which should be safe for
                # any possible request at the expense of speed.  In my testing,
                # though, it wasn't noticably slower than MFF_FAST.  If this
                # is observed to impact performance, consider creating a list
                # that maps API calls to the most appropriate flag.
                idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
                return holder[0]
            return call

        else:
            return val

IDAW = IDAWrapper()

# Some of the IDA API functions return generators that invoke thread-unsafe
# code during iteration.  Thus, making the initial API call via IDAW is not
# sufficient to have these underlying API calls be executed safely on the
# main thread.  This generator wraps those and performs the iteration safely.
def safe_generator(iterator):

    # Make the sentinel value something that isn't likely to be returned
    # by an API call (and isn't a fixed string that could be inserted into
    # a program to break FIRST maliciously)
    sentinel = '[1st] Sentinel %d' % (random.randint(0, 65535))

    holder = [sentinel] # need a holder, because 'global' sucks

    def trampoline():
        try:
            holder[0] = next(iterator)
        except StopIteration:
            holder[0] = sentinel
        return 1

    while True:
        # See notes above regarding why we use MFF_WRITE here
        idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
        if holder[0] == sentinel:
            return
        yield holder[0]

# End of FIRST plugin code

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
        """ MakeComm(int addr, string comment) => None
        Add a comment to the current IDB at the location `address`.
        Example: ida MakeComm 0x40000 "Important call here!"
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return IDAW.MakeComm(addr, comment)

    @expose
    def setcolor(self, address, color="0x005500"):
        """ SetColor(int addr [, int color]) => None
        Set the location pointed by `address` in the IDB colored with `color`.
        Example: ida SetColor 0x40000
        """
        addr = long(address, 16) if ishex(address) else long(address)
        color = long(color, 16) if ishex(color) else long(color)
        return IDAW.SetColor(addr, CIC_ITEM, color)

    @expose
    def makename(self, address, name):
        """ MakeName(int addr, string name]) => None
        Set the location pointed by `address` with the name specified as argument.
        Example: ida MakeName 0x4049de __entry_point
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return IDAW.MakeName(addr, name)

    @expose
    def jump(self, address):
        """ Jump(int addr) => None
        Move the IDA EA pointer to the address pointed by `addr`.
        Example: ida Jump 0x4049de
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return IDAW.Jump(addr)

    def getstructbyname(self, name):
        for (struct_idx, struct_sid, struct_name) in safe_generator(IDAW.Structs()):
            if struct_name == name:
                return struct_sid
        return None

    @expose
    def importstruct(self, struct_name):
        """ ImportStruct(string name) => dict
        Import an IDA structure in GDB which can be used with the `pcustom`
        command.
        Example: ida ImportStruct struct_1
        """
        if self.getstructbyname(struct_name) is None:
            return {}
        res = {struct_name: [x for x in safe_generator(IDAW.StructMembers(self.getstructbyname(struct_name)))]}
        return res

    @expose
    def importstructs(self):
        """ ImportStructs() => dict
        Import all structures from the current IDB into GDB, to be used with the `pcustom`
        command.
        Example: ida ImportStructs
        """
        res = {}
        for s in Structs():
            res.update(self.importstruct(s[2]))
        return res

    @expose
    def sync(self, offset, added, removed):
        """ Sync(offset, added, removed) => None
        Synchronize debug info with gef. This is an internal function. It is
        not recommended using it from the command line.
        """
        global _breakpoints, _current_instruction, _current_instruction_color

        if _current_instruction > 0:
            IDAW.SetColor(_current_instruction, CIC_ITEM, _current_instruction_color)

        base_addr = IDAW.get_imagebase()
        pc = base_addr + int(offset, 16)
        _current_instruction = long(pc)
        _current_instruction_color = IDAW.GetColor(_current_instruction, CIC_ITEM)
        IDAW.SetColor(_current_instruction, CIC_ITEM, 0x00ff00)
        print("PC @ " + hex(_current_instruction).strip('L'))
        # post it to the ida main thread to prevent race conditions
        IDAW.Jump(_current_instruction)

        cur_bps = set([ IDAW.GetBptEA(n)-base_addr for n in range(safe_generator(IDAW.GetBptQty())) ])
        ida_added = cur_bps - _breakpoints
        ida_removed = _breakpoints - cur_bps
        _breakpoints = cur_bps

        # update bp from gdb
        for bp in added:
            IDAW.AddBpt(base_addr+bp)
            _breakpoints.add(bp)
        for bp in removed:
            if bp in _breakpoints:
                _breakpoints.remove(bp)
            IDAW.DelBpt(base_addr+bp)

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
