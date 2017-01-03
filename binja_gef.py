"""
This script is the server-side of the XML-RPC defined for gef for
BinaryNinja.
It will spawn a threaded XMLRPC server from your current BN session
making it possible for gef to interact with Binary Ninja.

To install this script as a plugin:
$ ln -sf /path/to/gef/binja_gef.py ~/.binaryninja/plugins/binaryninja_gef.py

Then run it from Binary Ninja:
- open a disassembly session
- click "Tools" -> "gef : start/stop server"

If all went well, you will see something like
[+] Creating new thread for XMLRPC server: Thread-1
[+] Starting XMLRPC server: 0.0.0.0:1337
[+] Registered 10 functions.

@_hugsy_
"""

from binaryninja import *
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer, list_public_methods
import threading, string, inspect, xmlrpclib

HOST, PORT = "0.0.0.0", 1337
DEBUG = True
BP_HL_COLOR = 4

started = False
t = None
_breakpoints = set()
_current_instruction = 0


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

    def __init__(self, server, bv, *args, **kwargs):
        self.server = server
        self.view = bv
        self._version = ("Binary Ninja", core_version)
        return


    def _dispatch(self, method, params):
        """
        Plugin dispatcher
        """
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


    def get_function_by_addr(self, addr):
        """
        Retrieve a binaryninja.Function from its address, or None.
        """
        start_addr = self.view.get_previous_function_start_before(addr)
        func = self.view.get_function_at(self.view.platform, start_addr)
        return func

    @expose
    def shutdown(self):
        """ shutdown() => None
        Cleanly shutdown the XML-RPC service.
        Example: binaryninja shutdown
        """
        self.server.server_close()
        log_info("[+] XMLRPC server stopped")
        setattr(self.server, "shutdown", True)
        return 0

    @expose
    def version(self):
        """ version() => None
        Return a tuple containing the tool used and its version
        Example: binaryninja version
        """
        return self._version

    @expose
    def Jump(self, address):
        """ Jump(int addr) => None
        Move the EA pointer to the address pointed by `addr`.
        Example: binaryninja Jump 0x4049de
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return self.view.navigate(self.view, addr)

    @expose
    def MakeComm(self, address, comment):
        """ MakeComm(int addr, string comment) => None
        Add a comment at the location `address`.
        Example: binaryninja MakeComm 0x40000 "Important call here!"
        """
        addr = long(address, 16) if ishex(address) else long(address)
        func = self.get_function_by_addr(addr)
        return func.set_comment(addr, comment)

    @expose
    def SetColor(self, address, color='1'):
        """ SetColor(int addr [, int color]) => None
        Set the location pointed by `address` with `color`.
        Example: binaryninja SetColor 4
        """
        addr = long(address, 16) if ishex(address) else long(address)
        color = long(color, 16) if ishex(color) else long(color)
        return highlight(self.view, addr, color)

    @expose
    def Sync(self, pc, bps):
        """ Sync(bps) => None
        Synchronize debug info with gef. This is an internal function. It is
        not recommended using it from the command line.
        """
        global _breakpoints, _current_instruction

        # we use long() for pc because if using 64bits binaries might create
        # OverflowError for XML-RPC service
        pc = long(pc)

        # unhighlight the _current_instruction
        if _current_instruction > 0:
            highlight(self.view, _current_instruction, 0)
        highlight(self.view, pc, 2)

        # update the _current_instruction
        _current_instruction = pc

        # check if all BP defined in gef exists in session, if not set it
        # this allows to re-sync in case IDA/BN was closed
        for bp in bps:
            if bp not in _breakpoints:
                gef_add_breakpoint_to_list(self.view, bp)
            highlight(self.view, bp, BP_HL_COLOR)

        # if new breakpoints were manually added, sync them with gef
        _new = [ x for x in _breakpoints ]
        return _new


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def highlight(bv, addr, color):
    if DEBUG:
        log_info("Trying to highlight %#x with color %d" % (addr, color))
    start_addr = bv.get_previous_function_start_before(addr)
    func = bv.get_function_at(bv.platform, start_addr)
    if func is not None:
        func.set_user_instr_highlight(func.arch, addr, color)
    return


def start_service(host, port, bv):
    log_info("[+] Starting service on {}:{}".format(host, port))
    server = SimpleXMLRPCServer((host, port),
                                requestHandler=RequestHandler,
                                logRequests=False,
                                allow_none=True)
    server.register_introspection_functions()
    server.register_instance(Gef(server, bv))
    log_info("[+] Registered {} functions.".format( len(server.system_listMethods()) ))
    while True:
        if hasattr(server, "shutdown") and server.shutdown==True:
            break
        server.handle_request()
    return


def gef_start(bv):
    global t, started
    t = threading.Thread(target=start_service, args=(HOST, PORT, bv))
    t.daemon = True
    log_info("[+] Creating new thread {}".format(t.name))
    t.start()

    if not started:
        create_binja_menu()
        started = True
    return


def gef_stop(bv):
    global t
    t.join()
    t = None
    log_info("[+] Server stopped")
    return


def gef_start_stop(bv):
    if t is None:
        gef_start(bv)
        show_message_box("GEF", "Service successfully started, you can now have gef connect to it", OKButtonSet, InformationIcon)
    else:
        cli = xmlrpclib.ServerProxy("http://{:s}:{:d}".format(HOST, PORT))
        cli.shutdown()
        gef_stop(bv)
        show_message_box("GEF", "Service successfully stopped", OKButtonSet, InformationIcon)
    return


def gef_add_breakpoint_to_list(bv, addr):
    global  _breakpoints
    _breakpoints.add(addr)
    if DEBUG:
        log_info("Breakpoint to %#x added to queue" % addr)
    highlight(bv, addr, BP_HL_COLOR)
    return


def gef_del_breakpoint_from_list(bv, addr):
    global _breakpoints
    if addr not in _breakpoints:
        return
    _breakpoints.discard(addr)
    if DEBUG:
        log_info("Breakpoint to %#x removed from queue" % addr)
    highlight(bv, addr, 0)
    return


def create_binja_menu():
    # Binja does not really support menu in its GUI just yet
    PluginCommand.register_for_address("gef : add breakpoint",
                                       "Add a breakpoint in gef at the specified location.",
                                       gef_add_breakpoint_to_list)
    PluginCommand.register_for_address("gef : delete breakpoint",
                                       "Remove a breakpoint in gef at the specified location.",
                                       gef_del_breakpoint_from_list)
    return


PluginCommand.register("Start/stop server GEF interaction",
                       "Start/stop the XMLRPC server for communicating with gef",
                       gef_start_stop)
