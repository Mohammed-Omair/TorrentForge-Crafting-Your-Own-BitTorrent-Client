import json
import sys
import bencodepy
import hashlib
import requests
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
    print(decoded_result)


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
        peers(result, decoded_result)


if __name__ == "__main__":
    main()
