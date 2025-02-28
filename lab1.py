import pickle

# Physical Layer
class PhysicalLayer:
    def send(self, data: bytes) -> bytes:
        print("[PhysicalLayer] Sending data at bit level.")
        return data

    def receive(self, data: bytes) -> bytes:
        print("[PhysicalLayer] Receiving data at bit level.")
        return data

# Data Link Layer
class DataLinkLayer:
    def send(self, data: str, mac_address: str) -> bytes:
        print("[DataLinkLayer] Adding MAC address and framing.")
        frame = {'mac_address': mac_address, 'data': data}
        return pickle.dumps(frame)

    def receive(self, frame: bytes) -> str:
        print("[DataLinkLayer] Unframing and extracting data.")
        unpacked_frame = pickle.loads(frame)
        return unpacked_frame['data']

# Network Layer
class NetworkLayer:
    def send(self, data: str, ip_address: str) -> dict:
        print("[NetworkLayer] Adding IP address and routing.")
        packet = {'ip_address': ip_address, 'data': data}
        return packet

    def receive(self, packet: dict) -> str:
        print("[NetworkLayer] Extracting data from packet.")
        return packet['data']

# Transport Layer
class TransportLayer:
    def send(self, data: str, sequence_number: int) -> dict:
        print("[TransportLayer] Adding packet sequencing.")
        segment = {'sequence_number': sequence_number, 'data': data}
        return segment

    def receive(self, segment: dict) -> str:
        print("[TransportLayer] Handling sequencing and errors.")
        return segment['data']

# Session Layer
class SessionLayer:
    def send(self, data: str, session_id: str) -> dict:
        print("[SessionLayer] Managing session state.")
        session_data = {'session_id': session_id, 'data': data}
        return session_data

    def receive(self, session_data: dict) -> str:
        print("[SessionLayer] Restoring session state.")
        return session_data['data']

# Presentation Layer
class PresentationLayer:
    def send(self, data: str) -> str:
        print("[PresentationLayer] Encoding and compressing data.")
        encoded_data = data.encode('utf-8').hex()
        return encoded_data

    def receive(self, data: str) -> str:
        print("[PresentationLayer] Decoding and decompressing data.")
        return bytes.fromhex(data).decode('utf-8')

# Application Layer
class ApplicationLayer:
    def send(self, data: str) -> str:
        print("[ApplicationLayer] Creating HTTP-like request.")
        return f'GET / HTTP/1.1\nHost: example.com\n\n{data}'

    def receive(self, data: str) -> str:
        print("[ApplicationLayer] Parsing HTTP-like response.")
        return data.split('\n')[-1]

# Example Usage
if __name__ == '__main__':
    data = "Hello, OSI Model!"
    mac_address = "AA:BB:CC:DD:EE:FF"
    ip_address = "192.168.1.1"
    sequence_number = 1
    session_id = "session123"

    # Instantiate each layer
    app_layer = ApplicationLayer()
    pres_layer = PresentationLayer()
    sess_layer = SessionLayer()
    trans_layer = TransportLayer()
    net_layer = NetworkLayer()
    data_link_layer = DataLinkLayer()
    phys_layer = PhysicalLayer()

    # Sending Data (Top to Bottom)
    data = app_layer.send(data)
    data = pres_layer.send(data)
    data = sess_layer.send(data, session_id)
    data = trans_layer.send(data, sequence_number)
    data = net_layer.send(data, ip_address)
    data = data_link_layer.send(data, mac_address)
    data = phys_layer.send(data)

    print("\nData sent through OSI model successfully!\n")

    # Receiving Data (Bottom to Top)
    data = phys_layer.receive(data)
    data = data_link_layer.receive(data)
    data = net_layer.receive(data)
    data = trans_layer.receive(data)
    data = sess_layer.receive(data)
    data = pres_layer.receive(data)
    data = app_layer.receive(data)

    print("\nData received through OSI model successfully!")
    print("Final Output:", data)
