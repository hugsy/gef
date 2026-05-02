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

    exposed_gdb = gdb  # noqa: F821

    exposed_gef = gef  # noqa: F821


def start_rpyc_service(port: int = RPYC_PORT, bind_host: str = "127.0.0.1"):
    logging.info(f"RPYC service listening on {bind_host}:tcp/{port}")
    svc = rpyc.utils.server.OneShotServer(
        RemoteDebugService,
        hostname=bind_host,
        port=port,
        protocol_config={
            "allow_public_attrs": True,
        },
    )
    svc.start()
