import json
import sys
import bencodepy
import hashlib
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
    print(f"Tracker URL: {decoded_result['announce']} Length: {decoded_result['info']['length']} Info Hash: {info_dict} Piece Length: {decoded_result['info']['piece length']} Piece Hashed: {decoded_result['info']['pieces']}")  # Pretty-print the result as JSON

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
        info(sys.argv[-1])


if __name__ == "__main__":
    main()
