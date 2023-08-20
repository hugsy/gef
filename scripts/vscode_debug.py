import debugpy

DEBUGPY_PORT = 5678
debugpy.listen(DEBUGPY_PORT)
print("Waiting for debugger attach")
debugpy.wait_for_client()
print("Client connected, resuming session")
