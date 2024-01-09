import logging

import rpyc
import rpyc.core.protocol
import rpyc.utils.server

RPYC_PORT = 18812


class RemoteDebugService(rpyc.Service):
    def on_connect(self, conn: rpyc.core.protocol.Connection):
        logging.info(f"connect open: {str(conn)}")
        return

    def on_disconnect(self, conn: rpyc.core.protocol.Connection):
        logging.info(f"connection closed: {str(conn)}")
        return

    def exposed_eval(self, cmd):
        return eval(cmd)

    exposed_gdb = gdb

    exposed_gef = gef


def start_rpyc_service(port: int = RPYC_PORT):
    logging.info(f"RPYC service listening on tcp/{port}")
    svc = rpyc.utils.server.OneShotServer(
        RemoteDebugService,
        port=port,
        protocol_config={
            "allow_public_attrs": True,
        },
    )
    svc.start()
