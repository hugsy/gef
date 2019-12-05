"""
Heap Made Easy - Heap Analysis and Collaboration Tool
https://heapme.f2tc.com/

@htejeda
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time
import json
import requests

_heapme_events = []

_hm_lock = threading.Lock()
_hm_thr_event = threading.Event()
_hm_stop_running = False

LOG_SRV_HOST = '127.0.0.1'
LOG_SRV_PORT = 4327

@register_command
class HeapMe(GenericCommand):
    """Heap Made Easy

init -- Connect to the HeapMe URL and begins tracking dynamic heap allocation
watch -- Updates the heap layout when this breakpoint is hit
push -- Uploads all events to the HeapME URL
"""

    _cmdline_ = "heapme"
    _syntax_  = "{:s} (init|watch|push)".format(_cmdline_)

    def __init__(self):
        super(HeapMe, self).__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.usage()
        return

@register_command
class HeapMeInit(GenericCommand):
    """Connect to the HeapMe URL and begins tracking dynamic heap allocation"""

    _cmdline_ = "heapme init"
    _syntax_  = "{:s} <url> <key>".format(_cmdline_)
    _example_ = "{0:s} https://heapme.f2tc.com/1a2b3c4d5e6f7g8h9i0j 1a2b3c4d-1a2b-1a2b-1a2b-1a2b3c4d5e6f".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        global _heapme_events, thr_updater

        if not argv or len(argv) != 2:
            self.usage()
            return

        print(r"""
             _   _                  __  __ _____
            | | | | ___  __ _ _ __ |  \/  | ____|
            | |_| |/ _ \/ _` | '_ \| |\/| |  _|
            |  _  |  __/ (_| | |_) | |  | | |___
            |_| |_|\___|\__,_| .__/|_|  |_|_____|
                             |_|
        """.center(40))

        _heapme_url = "{0:s}/{1:s}".format(argv[0], argv[1])
        req = requests.get(_heapme_url)
        data = req.json()

        if 'result' in data:
            warn("{0}: {1} - {2}".format(
                Color.colorify("HeapME", "blue"),
                Color.colorify(_heapme_url, "underline blue"),
                Color.colorify(data['result'], "red")
            ))

            return False

        if not data['is_empty']:
            if not self.confirm("oOps!, the specified URL contains data of previous analysis, do you want to overwrite it? [y/n] "):
                print("Bye!")
                return

        ok("{0}: connected to {1}".format(
            Color.colorify("HeapME", "blue"),
            Color.colorify(argv[0], "underline blue"),
        ))

        _sec = checksec(get_filepath())

        _heapme_events.append({
            'type': 'begin',
            'filepath': get_filepath(),
            'checksec': {
                'Canary': _sec["Canary"],
                'NX': _sec["NX"],
                'PIE': _sec["PIE"],
                'Fortify': _sec["Fortify"],
                'RelRO': "Full" if _sec["Full RelRO"] else "Partial" if _sec["Partial RelRO"] else "No"
            }
        })

        set_gef_setting("heapme.push_on_update", True, bool, "Push events on each update")
        set_gef_setting("heapme.wait_before_push", 5, bool, "Wait before push")
        set_gef_setting("heapme.enabled", True, bool, "HeapME is Enablbed")
        set_gef_setting("heapme.url", _heapme_url, str, "HeapME URL")
        gef_on_exit_hook(self.clean)

        if not hm_thr_updater.is_alive():
            hm_thr_updater.start()

        if not hm_thr_log_srv.is_alive():
            hm_thr_log_srv.start()

        heapme_push()

    @gef_heap_event("__libc_malloc", "__libc_calloc", "__libc_realloc", "__libc_free")
    def heap_event(**kwargs):
        global _heapme_events

        if not get_gef_setting("heapme.enabled"):
            err("HeapME is not enabled, run 'heapme init' first")
            return

        _heapme_events.append({
            "type": kwargs["name"],
            "data": {
                "address": kwargs["address"],
                "size": -1 if kwargs["name"] == "__libc_free" else kwargs["size"]
            }
        })

        heapme_update()

    def confirm(self, msg):

        valid = { "y": True, "yes": True, "n": False, "no": False }

        while True:
            choice = input(msg)

            if choice in valid:
                return valid[choice]
            else:
                print("Please respond with 'y' or 'n' (or 'yes' or 'no')")

    def clean(self, event):
        global _heapme_events, _hm_stop_running

        print("Hold on, {0} is exiting cleanly".format(Color.colorify("HeapME", "blue")), end="...")

        _heapme_events.append({'type': 'done'})
        heapme_push()

        if get_gef_setting("heapme.push_on_update"):
            _hm_stop_running = True
            _hm_thr_event.set()

        print("Adios!")
        gef_on_exit_unhook(self.clean)

@register_command
class HeapMeWatch(GenericCommand):
    """Updates the heap layout when this breakpoint is hit"""

    _cmdline_ = "heapme watch"
    _syntax_  = "{:s} <address>".format(_cmdline_)
    _example_ = "{0:s} *0x0xbadc0ffee0ddf00d".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):

        if not argv or len(argv) != 1:
            self.usage()
            return

        if not get_gef_setting("heapme.enabled"):
            err("HeapME is not enabled, run 'heapme init' first")
            return

        HeapMeWatchAddress(argv[0])
        ok("HeapMe will update the heap chunks when the {0:s} breakpoint is hit".format(Color.colorify(argv[0], "yellow")))

@register_command
class HeapMePush(GenericCommand):
    """Uploads all events to the HeapME URL"""

    _cmdline_ = "heapme push"
    _syntax_  = "{:s}".format(_cmdline_)
    _example_ = "{0:s}".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):

        if not get_gef_setting("heapme.enabled"):
            err("HeapME is not enabled, run 'heapme init' first")
            return

        heapme_push()

class HeapMeWatchAddress(gdb.Breakpoint):
    def stop(self):
        heapme_update()

        return False

def _get_heap_segment():

    heap_section = [x for x in get_process_maps() if x.path == "[heap]"]
    if not heap_section:
        err("No heap section")
        return

    arena = get_main_arena()
    if arena is None:
        err("No valid arena")
        return

    heap_section = heap_section[0].page_start

    top_chunk_addr = int(arena.top)
    view_size = (top_chunk_addr - heap_section + 16) / 8
    cmd = "x/%dxg %s" % (view_size, heap_section)

    heap_region = gdb.execute(cmd, to_string=True)
    return heap_region

def heapme_update():

    global _heapme_events, _hm_lock

    #Used to restore previous gef.disable_color setting
    _prev_gef_disable_color = get_gef_setting("gef.disable_color")

    #Temporarily disable color to simplify parsing
    set_gef_setting("gef.disable_color", True)

    arenas = {'type': 'arenas', 'data': False}
    try:
        arena = GlibcArena(__gef_default_main_arena__)
        arenas = {'type': 'arenas', 'data': str(arena)}

    except gdb.error:
        arenas = {'type': 'arenas', 'data': False}
        return

    fast     = gdb.execute("heap bins fast", to_string=True)
    tcache   = gdb.execute("heap bins tcache", to_string=True)
    unsorted = gdb.execute("heap bins unsorted", to_string=True)
    small    = gdb.execute("heap bins small", to_string=True)
    large    = gdb.execute("heap bins large", to_string=True)
    chunks   = gdb.execute("heap chunks", to_string=True)

    _new_event = [
        arenas,
        { 'type':'fast', 'data': str(fast) },
        { 'type':'tcache', 'data': str(tcache) },
        { 'type':'unsorted', 'data': str(unsorted) },
        { 'type':'small', 'data': str(small) },
        { 'type':'large', 'data': str(large) },
        { 'type':'chunks', 'chunks_summary': str(chunks), 'data': _get_heap_segment() }
    ]

    _hm_lock.acquire()
    _heapme_events.extend(_new_event)
    _hm_lock.release()

    #Restore previous setting
    set_gef_setting("gef.disable_color", _prev_gef_disable_color)

    if get_gef_setting("heapme.push_on_update"):
        _hm_thr_event.set()

def heapme_push():
    global _heapme_events, _hm_lock, _hm_thr_event

    if not get_gef_setting("heapme.enabled"):
        err("HeapME is not enabled, run 'heapme init' first")
        return

    _hm_lock.acquire()

    if not _heapme_events:
        _hm_lock.release()
        return

    res = requests.post(get_gef_setting("heapme.url"), json={ 'events': _heapme_events })

    if res.status_code != 200:
        print("{0:s}: Error uploading event".format(Color.colorify("HeapME", "blue")))
        _hm_lock.release()
        return

    _heapme_events = []

    _hm_lock.release()
    _hm_thr_event.clear()

class HeapmeLogServerHandler(BaseHTTPRequestHandler):

    def do_POST(self):

        if self.headers['content-type'] == 'application/json':
            length = int(self.headers['content-length'])
            body = self.rfile.read(length)
            self.send_response(200)
            self.end_headers()

            obj = json.loads(body.decode('utf-8'))
            if not isinstance(obj, dict) or 'msg' not in obj.keys():
                self.send_error(400, "'msg' field not found")
                return

            _heapme_events.append({
                'type': 'log',
                'data': obj['msg']
            })

        else:
            self.send_error(415, "Only JSON data is supported.")
            return

    def log_message(self, format, *args):
        return

def _heapme_log_server():
    httpd = HTTPServer((LOG_SRV_HOST, LOG_SRV_PORT), HeapmeLogServerHandler)
    while not _hm_stop_running:
        httpd.handle_request()

hm_thr_log_srv = threading.Thread(target=_heapme_log_server, args=())
hm_thr_log_srv.daemon = True

def heapme_event_consumer(e):
    """Wait for an event to be set before doing anything."""

    # We wait N seconds to avoid POSTing on each update (Default 5)
    wait_before_push = get_gef_setting("heapme.wait_before_push")
    if not wait_before_push:
        wait_before_push = 5

    while True:
        e.wait()

        if _hm_stop_running:
            break

        time.sleep(wait_before_push)
        heapme_push()

hm_thr_updater = threading.Thread(
    target=heapme_event_consumer,
    args=(_hm_thr_event,)
)

register_external_command(HeapMe())
