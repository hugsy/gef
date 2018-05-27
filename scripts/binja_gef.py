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
import threading, string, inspect, xmlrpclib, copy

HOST, PORT = "0.0.0.0", 1337
DEBUG = True
HL_NO_COLOR = enums.HighlightStandardColor.NoHighlightColor
HL_BP_COLOR = enums.HighlightStandardColor.RedHighlightColor
HL_CUR_INSN_COLOR = enums.HighlightStandardColor.GreenHighlightColor

started = False
t = None
_breakpoints = set()
_current_instruction = 0

PAGE_SZ = 0x1000

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
        self.base = bv.entry_point & ~(PAGE_SZ-1)
        self._version = ("Binary Ninja", core_version)
        self.old_bps = set()
        return


    def _dispatch(self, method, params):
        """
        Plugin dispatcher
        """
        func = getattr(self, method)
        if not is_exposed(func):
            raise NotImplementedError('Method "%s" is not exposed' % method)

        if DEBUG:
            log_info("[+] Executing %s(%s)" % (method, params))
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
        return self.view.file.navigate(self.view.file.view, addr)

    @expose
    def MakeComm(self, address, comment):
        """ MakeComm(int addr, string comment) => None
        Add a comment at the location `address`.
        Example: binaryninja MakeComm 0x40000 "Important call here!"
        """
        addr = long(address, 16) if ishex(address) else long(address)
        start_addr = self.view.get_previous_function_start_before(addr)
        func = self.view.get_function_at(start_addr)
        return func.set_comment(addr, comment)

    @expose
    def SetColor(self, address, color='0xff0000'):
        """ SetColor(int addr [, int color]) => None
        Set the location pointed by `address` with `color`.
        Example: binaryninja SetColor 0x40000 0xff0000
        """
        addr = long(address, 16) if ishex(address) else long(address)
        color = long(color, 16) if ishex(color) else long(color)
        R,G,B = (color >> 16)&0xff, (color >> 8)&0xff, (color&0xff)
        color = highlight.HighlightColor(red=R, blue=G, green=B)
        return hl(self.view, addr, color)

    @expose
    def Sync(self, off, added, removed):
        """ Sync(off, added, removed) => None
        Synchronize debug info with gef. This is an internal function. It is
        not recommended using it from the command line.
        """
        global _breakpoints, _current_instruction

        # we use long() for pc because if using 64bits binaries might create
        # OverflowError for XML-RPC service
        off = long(off, 16) if ishex(off) else long(off)
        pc = self.base + off
        if DEBUG: log_info("[*] current_pc=%#x , old_pc=%#x" % (pc, _current_instruction))

        # unhighlight the _current_instruction
        if _current_instruction > 0:
            hl(self.view, _current_instruction, HL_NO_COLOR)
        hl(self.view, pc, HL_CUR_INSN_COLOR)

        # update the _current_instruction
        _current_instruction = pc

        if DEBUG:
            log_info("[*] pre-gdb-add-breakpoints: %s" % (added,))
            log_info("[*] pre-gdb-del-breakpoints: %s" % (removed,))
            log_info("[*] pre-binja-breakpoints: %s" % (_breakpoints))

        bn_added = [ x-self.base for x in _breakpoints if x not in self.old_bps ]
        bn_removed = [ x-self.base for x in self.old_bps if x not in _breakpoints ]

        for bp in added:
            gef_add_breakpoint_to_list(self.view, self.base + bp)

        for bp in removed:
            gef_del_breakpoint_from_list(self.view, self.base + bp)

        self.old_bps = copy.deepcopy(_breakpoints)

        if DEBUG:
            log_info("[*] post-gdb-add-breakpoints: %s" % (bn_added,))
            log_info("[*] post-gdb-del-breakpoints: %s" % (bn_removed,))
            log_info("[*] post-binja-breakpoints: %s" % (_breakpoints,))
        return [bn_added, bn_removed]


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def hl(bv, addr, color):
    if DEBUG: log_info("[*] hl(%#x, %s)" % (addr, color))
    start_addr = bv.get_previous_function_start_before(addr)
    func = bv.get_function_at(start_addr)
    if func is None: return
    func.set_user_instr_highlight(addr, color)
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
        if hasattr(server, "shutdown") and server.shutdown==True: break
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
        show_message_box("GEF", "Service successfully started, you can now have gef connect to it",
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)

    else:
        try:
            cli = xmlrpclib.ServerProxy("http://{:s}:{:d}".format(HOST, PORT))
            cli.shutdown()
        except socket.error:
            pass
        gef_stop(bv)
        show_message_box("GEF", "Service successfully stopped",
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
    return


def gef_add_breakpoint_to_list(bv, addr):
    global  _breakpoints
    if addr in _breakpoints: return False
    _breakpoints.add(addr)
    log_info("[+] Breakpoint %#x added" % addr)
    hl(bv, addr, HL_BP_COLOR)
    return True


def gef_del_breakpoint_from_list(bv, addr):
    global _breakpoints
    if addr not in _breakpoints: return False
    _breakpoints.discard(addr)
    log_info("[+] Breakpoint %#x removed" % addr)
    hl(bv, addr, HL_NO_COLOR)
    return True


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
