from fastapi import WebSocket


class WSManager:

    def __init__(self):

        self.clients=[]

    async def connect(
        self,
        ws:WebSocket
    ):

        await ws.accept()

        self.clients.append(ws)

    def disconnect(
        self,
        ws:WebSocket
    ):

        if ws in self.clients:

            self.clients.remove(ws)

    async def broadcast(
        self,
        data
    ):

        dead=[]

        for ws in self.clients:

            try:

                await ws.send_json(data)

            except:

                dead.append(ws)

        for ws in dead:

            self.disconnect(ws)


manager=WSManager()