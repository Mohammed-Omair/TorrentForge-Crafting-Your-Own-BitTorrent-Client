import json
import sys
import bencodepy
import hashlib
import requests
import struct
import socket
import math

def decode_bytes(obj):
    """
    Recursively decode all bytes objects in a nested structure.
    """
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")  # Decode bytes to string if possible
        except UnicodeDecodeError:
            return obj.hex()  # Return as hex string for binary data
    elif isinstance(obj, list):
        return [decode_bytes(item) for item in obj]  # Decode elements in the list
    elif isinstance(obj, dict):
        return {decode_bytes(key): decode_bytes(value) for key, value in obj.items()}  # Decode dict keys and values
    else:
        return obj  # Return non-bytes objects as-is

def info(file):
    with open(file, 'rb') as f_in:
        data = f_in.read()
    result = bencodepy.decode(data)  # Decode the bencoded value
    decoded_result = decode_bytes(result)  # Recursively decode bytes objects
    info_dict = bencodepy.encode(result[b'info'])
    info_dict = hashlib.sha1(info_dict).hexdigest()
    return result, decoded_result

def peers(result, decoded_result):
    info_dict_byte = bencodepy.encode(result[b'info'])
    info_dict_byte = hashlib.sha1(info_dict_byte).digest()
    payload = {'info_hash': info_dict_byte, 'peer_id': "imomairutamasterscse", 'port': 6881, 'uploaded': 0, 'downloaded': 0, 'left': decoded_result['info']['length'], 'compact': 1}
    r = requests.get(decoded_result['announce'], params=payload)
    result = bencodepy.decode(r.content)  # Decode the bencoded value
    decoded_result = decode_bytes(result)
    peer_bytes = result[b'peers']
    peer_list = []

    # Each peer is represented by 6 bytes (4 for IP, 2 for port)
    for i in range(0, len(peer_bytes), 6):
        ip_bytes = peer_bytes[i:i+4]
        port_bytes = peer_bytes[i+4:i+6]
        
        # Convert IP bytes to a human-readable string
        ip_address = socket.inet_ntoa(ip_bytes)
        
        # Convert port bytes to an integer
        port = struct.unpack('!H', port_bytes)[0]
        
        # Append as a tuple
        peer_list.append(f"{ip_address}:{port}")

    # Print the decoded peers
    return peer_list

def handshake(result, address):
    ip, port = address.split(":")
    port = int(port)

    # Prepare handshake message
    pstr = b"BitTorrent protocol"  # Protocol string
    pstrlen = len(pstr)  # Length of protocol string
    reserved = b"\x00" * 8  # Reserved bytes
    info_hash = hashlib.sha1(bencodepy.encode(result[b'info'])).digest()  # SHA1 info hash
    peer_id = b"imomairutamasterscse"  # Peer ID (must be 20 bytes)
    handshake_msg = struct.pack("B", pstrlen) + pstr + reserved + info_hash + peer_id

    # Establish a TCP connection and send the handshake
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, port))
        s.sendall(handshake_msg)

        # Receive handshake response
        response = s.recv(68)  # Handshake response is always 68 bytes

        # Validate response
        if response[1:20] != pstr:
            raise ValueError("Invalid protocol string in response.")
        if response[28:48] != info_hash:
            raise ValueError("Info hash mismatch in handshake response.")
    except Exception as e:
        print(f"Handshake failed: {e}")
    decoded_result = decode_bytes(response)
    print(f"Peer ID: {decoded_result[-40:]}")
    return s

def download_piece(address, s, decoded_result, piece_index):
    piece_length = decoded_result['info']['piece length']
    no_pieces = math.ceil(piece_length/16384)
    print(no_pieces)
    print(piece_length)
    ip, port = address.split(":")
    port = int(port)
    try:
        response = s.recv(2048)
        print(response)
        s.sendall(b'\x00\x00\x00\x02\x02')
        response = s.recv(2048)
        print(response)
        msg_id = b'\x06'
        length = 262144
        #for i in range(no_pieces):
            #payload = piece_index + begin + length
            #msg = msg_lngth + msg_id + payload

    except Exception as e:
        print(f"Failed: {e}")

def main():
    command = sys.argv[1]

    # Debugging print statements will appear in stderr
    print("Logs from your program will appear here!", file=sys.stderr)

    if command == "decode":
        bencoded_value = sys.argv[2].encode('utf-8')  # Convert input to bytes
        result = bencodepy.decode(bencoded_value)  # Decode the bencoded value
        decoded_result = decode_bytes(result)  # Recursively decode bytes objects
        print(json.dumps(decoded_result))  # Pretty-print the result as JSON
    elif command == "info":
        result, decoded_result = info(sys.argv[-1])
        info_dict = bencodepy.encode(result[b'info'])
        info_dict = hashlib.sha1(info_dict).hexdigest()
        print(f"Tracker URL: {decoded_result['announce']} Length: {decoded_result['info']['length']} Info Hash: {info_dict} Piece Length: {decoded_result['info']['piece length']} Piece Hashed: {decoded_result['info']['pieces']}")
    elif command == 'peers':
        result, decoded_result = info(sys.argv[-1])
        peer_list = peers(result, decoded_result)
        print(peer_list)
    elif command == "handshake":
        address = sys.argv[-1]
        result, decoded_result = info(sys.argv[-2])
        s = handshake(result, address)
    elif command == "download_piece":
        result, decoded_result = info(sys.argv[-2])
        piece_index = sys.argv[-1]
        print(result)
        print(decoded_result)
        peer_list = peers(result, decoded_result)
        print(peer_list)
        s = handshake(result, peer_list[0])
        download_piece(peer_list[0], s, decoded_result, piece_index)


if __name__ == "__main__":
    main()
