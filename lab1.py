import json
import logging
from typing import Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Physical Layer
class PhysicalLayer:
    def send(self, data: bytes) -> bytes:
        logging.info("[PhysicalLayer] Sending data at bit level.")
        return data

    def receive(self, data: bytes) -> bytes:
        logging.info("[PhysicalLayer] Receiving data at bit level.")
        return data

# Data Link Layer
class DataLinkLayer:
    def send(self, data: str, mac_address: str) -> bytes:
        if not self._validate_mac_address(mac_address):
            raise ValueError("Invalid MAC address format.")
        logging.info("[DataLinkLayer] Adding MAC address and framing.")
        frame = {'mac_address': mac_address, 'data': data}
        return json.dumps(frame).encode('utf-8')

    def receive(self, frame: bytes) -> str:
        logging.info("[DataLinkLayer] Unframing and extracting data.")
        try:
            unpacked_frame = json.loads(frame.decode('utf-8'))
            return unpacked_frame.get('data', '')
        except Exception as e:
            logging.error(f"[DataLinkLayer] Error during unframing: {e}")
            return ""

    def _validate_mac_address(self, mac_address: str) -> bool:
        return isinstance(mac_address, str) and len(mac_address.split(':')) == 6

# Network Layer
class NetworkLayer:
    def send(self, data: str, ip_address: str) -> dict:
        logging.info("[NetworkLayer] Adding IP address and routing.")
        packet = {'ip_address': ip_address, 'data': data}
        return packet

    def receive(self, packet: dict) -> str:
        logging.info("[NetworkLayer] Extracting data from packet.")
        return packet.get('data', '')

# Transport Layer (TCP/UDP Simulation)
class TransportLayer:
    def send(self, data: str, sequence_number: int, protocol: str = 'TCP') -> dict:
        logging.info(f"[TransportLayer] Adding packet sequencing using {protocol}.")
        segment = {'sequence_number': sequence_number, 'protocol': protocol, 'data': data}
        return segment

    def receive(self, segment: dict) -> str:
        logging.info("[TransportLayer] Handling sequencing and errors.")
        return segment.get('data', '')

# Session Layer
class SessionLayer:
    active_sessions = set()

    def send(self, data: str, session_id: str) -> dict:
        if session_id not in self.active_sessions:
            self.active_sessions.add(session_id)
            logging.info(f"[SessionLayer] Establishing session {session_id}.")
        return {'session_id': session_id, 'data': data}

    def receive(self, session_data: dict) -> str:
        logging.info("[SessionLayer] Restoring session state.")
        return session_data.get('data', '')

    def close_session(self, session_id: str):
        if session_id in self.active_sessions:
            self.active_sessions.remove(session_id)
            logging.info(f"[SessionLayer] Closing session {session_id}.")

# Presentation Layer (With Encryption/Decryption)
class PresentationLayer:
    def send(self, data: str) -> str:
        logging.info("[PresentationLayer] Encoding and encrypting data.")
        encoded_data = data.encode('utf-8').hex()
        return encoded_data

    def receive(self, data: str) -> str:
        logging.info("[PresentationLayer] Decoding and decrypting data.")
        return bytes.fromhex(data).decode('utf-8')

# Application Layer (Supporting HTTP and FTP Simulation)
class ApplicationLayer:
    def send(self, data: str, protocol: str = 'HTTP') -> str:
        logging.info(f"[ApplicationLayer] Creating {protocol} request.")
        if protocol == 'HTTP':
            return f'GET / HTTP/1.1\nHost: example.com\n\n{data}'
        elif protocol == 'FTP':
            return f'USER anonymous\nPASS guest\nDATA: {data}'
        else:
            raise ValueError("Unsupported application protocol.")

    def receive(self, data: str) -> str:
        logging.info("[ApplicationLayer] Parsing response.")
        return data.split('\n')[-1]

# Example Usage
if __name__ == '__main__':
    data = "Hello, OSI Model!"
    mac_address = "AA:BB:CC:DD:EE:FF"
    ip_address = "192.168.1.1"
    sequence_number = 1
    session_id = "session123"
    protocol = 'TCP'

    # Instantiate each layer
    app_layer = ApplicationLayer()
    pres_layer = PresentationLayer()
    sess_layer = SessionLayer()
    trans_layer = TransportLayer()
    net_layer = NetworkLayer()
    data_link_layer = DataLinkLayer()
    phys_layer = PhysicalLayer()

    # Sending Data (Top to Bottom)
    data = app_layer.send(data, 'HTTP')
    data = pres_layer.send(data)
    data = sess_layer.send(data, session_id)
    data = trans_layer.send(data, sequence_number, protocol)
    data = net_layer.send(data, ip_address)
    data = data_link_layer.send(data, mac_address)
    data = phys_layer.send(data)

    logging.info("\nData sent through OSI model successfully!\n")

    # Receiving Data (Bottom to Top)
    data = phys_layer.receive(data)
    data = data_link_layer.receive(data)
    data = net_layer.receive(data)
    data = trans_layer.receive(data)
    data = sess_layer.receive(data)
    data = pres_layer.receive(data)
    data = app_layer.receive(data)

    logging.info("\nData received through OSI model successfully!")
    logging.info("Final Output: " + data)

    # Close session
    sess_layer.close_session(session_id)
