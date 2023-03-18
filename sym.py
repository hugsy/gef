class NewCommand(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "newcmd"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        # do anything allowed by gef, for example show the current running
        # architecture as Python object:
        print(" = {}".format(current_arch) )
        # or showing the current $pc
        print("pc = {:#x}".format(current_arch.pc))
        return

register_external_command(NewCommand())
