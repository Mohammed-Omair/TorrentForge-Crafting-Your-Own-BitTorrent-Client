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

def msg(s):
    # Receive the bitfield or any other message (read and discard for now)
    response = s.recv(2048)
    print("Received from peer:", response)

    # Send 'interested' message
    s.sendall(b'\x00\x00\x00\x01\x02')  # length(1) + message ID(2)
    print("Sent 'interested' message")

    # Wait for 'unchoke' message
    while True:
        response = s.recv(2048)
        print("Received from peer:", response)
        msg_length = struct.unpack(">I", response[:4])[0]
        msg_id = response[4]
        if msg_id == 1:  # Unchoke message
            print("Received 'unchoke' message")
            break



def download_piece(s, decoded_result, result, piece_index):
    """
    Downloads a piece from the peer, saves it to the specified directory, and verifies its hash.
    """
    piece_length = decoded_result['info']['piece length']
    block_size = 16 * 1024  # 16 KiB
    total_blocks = math.ceil(piece_length / block_size)
    piece_index = int(piece_index)  # Ensure the piece_index is an integer
    
    
    # # Receive the bitfield or any other message (read and discard for now)
    # response = s.recv(2048)
    # print("Received from peer:", response)

    # # Send 'interested' message
    # s.sendall(b'\x00\x00\x00\x01\x02')  # length(1) + message ID(2)
    # print("Sent 'interested' message")

    # # Wait for 'unchoke' message
    # while True:
    #     response = s.recv(2048)
    #     print("Received from peer:", response)
    #     msg_length = struct.unpack(">I", response[:4])[0]
    #     msg_id = response[4]
    #     if msg_id == 1:  # Unchoke message
    #         print("Received 'unchoke' message")
    #         break

    # Prepare to collect blocks
    piece_data = b""  # To store the combined blocks
    total_blocks = math.ceil(piece_length / block_size)

    # Adjust total_blocks for the last piece if necessary
    if piece_index == (decoded_result['info']['length'] // piece_length):  # Last piece
        remaining_length = decoded_result['info']['length'] % piece_length
        if remaining_length > 0:
            total_blocks = math.ceil(remaining_length / block_size)

    for block_idx in range(total_blocks):
        begin = block_idx * block_size
        length = block_size

        # Adjust the length for the last block in the piece
        if piece_index == (decoded_result['info']['length'] // piece_length) and block_idx == total_blocks - 1:
            length = (decoded_result['info']['length'] % piece_length) % block_size or (decoded_result['info']['length'] % piece_length)

        # Construct the request message
        msg_length = struct.pack(">I", 13)  # Message length (4 bytes)
        msg_id = b'\x06'  # Message ID for request
        payload = struct.pack(">III", piece_index, begin, length)
        request_message = msg_length + msg_id + payload

        # Send the request message
        s.sendall(request_message)
        # Read the response
        buffer = b""
        while len(buffer) < 13 + length:
            part = s.recv(16384 + 13)  # Read more data until full message is received
            if not part:
                raise ConnectionError("Peer closed the connection.")
            buffer += part

        # Validate and parse the piece message
        msg_length = struct.unpack(">I", buffer[:4])[0]
        msg_id = buffer[4]
        if msg_id != 7:  # Ensure it's a piece message
            raise ValueError(f"Unexpected message ID: {msg_id}")

        # Extract the block data
        block_data = buffer[13:]  # Skip length (4), msg_id (1), index (4), begin (4)
        piece_data += block_data

    # Verify the piece's hash
    expected_hash = result[b'info'][b'pieces'][piece_index * 20:(piece_index + 1) * 20]
    actual_hash = hashlib.sha1(piece_data).digest()
    # print(f"Expected Hash: {expected_hash}")
    # print(f"Actual Hash: {actual_hash}")
    if actual_hash != expected_hash:
        raise ValueError("Piece hash mismatch. Downloaded data is corrupted.")
    print("Piece downloaded and verified successfully.")

    # Save the piece to the specified output directory

    
    return piece_data

from threading import Thread, Lock

def download_piece_thread(peer_list, piece_index, result, decoded_result, output_data, lock):
    """
    Thread function to download a piece and save it to shared output data.
    """
    for peer in peer_list:
        try:
            s = handshake(result, peer)
            msg(s)
            piece_data = download_piece(s, decoded_result, result, piece_index)
            s.close()
            
            # Save the piece data with a thread-safe lock
            with lock:
                output_data[piece_index] = piece_data
            return  # Exit the function on successful download
        except Exception as e:
            print(f"Error downloading piece {piece_index} from peer {peer}: {e}")
    raise RuntimeError(f"Failed to download piece {piece_index} from all peers.")

def download_torrent(decoded_result, result, output_path, peer_list):
    """
    Downloads the entire file specified in the torrent file using multi-threading and saves it to disk.
    """
    file_length = decoded_result['info']['length']
    piece_length = decoded_result['info']['piece length']
    num_pieces = math.ceil(file_length / piece_length)

    print(f"Total file length: {file_length}")
    print(f"Piece length: {piece_length}")
    print(f"Number of pieces: {num_pieces}")

    # Prepare shared data structures
    output_data = [None] * num_pieces  # To store downloaded pieces
    lock = Lock()

    # Create and start threads
    threads = []
    for piece_index in range(num_pieces):
        thread = Thread(target=download_piece_thread, args=(peer_list, piece_index, result, decoded_result, output_data, lock))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Combine pieces and save the file
    with open(output_path, "wb") as file:
        for piece_index, piece_data in enumerate(output_data):
            if piece_data is None:
                raise RuntimeError(f"Missing data for piece {piece_index}. Download incomplete.")
            file.write(piece_data)

    print(f"File downloaded successfully and saved to {output_path}")





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
        info_dict = bencodepy.encode(result[b'info'])
        info_dict = hashlib.sha1(info_dict).hexdigest()
        peer_list = peers(result, decoded_result)
        s = handshake(result, peer_list[0])
        msg(s)
        piece_data = download_piece(s, decoded_result, result, sys.argv[-1])
        # Save the piece to the specified output directory
        with open(sys.argv[-3], "wb") as file:
            file.write(piece_data)
        print(f"Piece saved to {sys.argv[-3]}")
    elif command == "download":
        result, decoded_result = info(sys.argv[-1])
        output_path = sys.argv[-2]
        peer_list = peers(result, decoded_result)
        # Handshake with the first peer
        # Download the torrent file
        download_torrent(decoded_result, result, output_path, peer_list)


if __name__ == "__main__":
    main()
