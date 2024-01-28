import socket
import os
import hashlib
import hmac
from Crypto.Cipher import AES
import struct
from datetime import datetime
import time
import random
import json
import datetime

AUTH_SUCCESS = bytes([0x22])
AUTH_FAILED = bytes([0x11])
DATA_SUCCESS = bytes([0x44])
DATA_FAILED =  bytes([0x33])

DATA_FRAME = bytearray([0x0F])
AUTH_FRAME = bytearray([0xFF])
PROTO_VERSION = bytearray([0x00])

def create_bytearray():
    # Dummy-Werte für jede Größe, du kannst sie durch sinnvolle Werte ersetzen
    epoch = int(time.time())
    voltage_scale = -1
    voltage_L1 = 2300+random.randint(0, 60)
    voltage_L2 = 2300+random.randint(0, 60)
    voltage_L3 = 2300+random.randint(0, 60)
    current_scale = -2
    current_L1 = random.randint(0, 3000)
    current_L2 = random.randint(0, 3000)
    current_L3 = random.randint(0, 3000)
    power_scale = -3
    active_power_plus = random.randint(0, 3000)
    active_power_minus = random.randint(0, 3000)
    reactive_power_plus = random.randint(0, 3000)
    reactive_power_minus = random.randint(0, 3000)
    energy_scale = -3
    energy_plus = random.randint(1000, 3000)
    energy_minus = random.randint(1000, 3000)

    # Verpacke die Werte in das Byte-Array
    byte_array = bytearray()
    byte_array.extend(struct.pack("I", epoch))
    byte_array.extend(struct.pack("b", voltage_scale))
    byte_array.extend(struct.pack("h", voltage_L1))
    byte_array.extend(struct.pack("h", voltage_L2))
    byte_array.extend(struct.pack("h", voltage_L3))
    byte_array.extend(struct.pack("b", current_scale))
    byte_array.extend(struct.pack("h", current_L1))
    byte_array.extend(struct.pack("h", current_L2))
    byte_array.extend(struct.pack("h", current_L3))
    byte_array.extend(struct.pack("b", power_scale))
    byte_array.extend(struct.pack("I", active_power_plus))
    byte_array.extend(struct.pack("I", active_power_minus))
    byte_array.extend(struct.pack("b", energy_scale))
    byte_array.extend(struct.pack("I", energy_plus))
    byte_array.extend(struct.pack("I", energy_minus))

    return byte_array

def print_data(plaintext):
    epoch = struct.unpack("I", plaintext[0:4])[0]

    voltage_scale = struct.unpack("b", plaintext[4:5])[0]
    voltage_L1 = struct.unpack("h", plaintext[5:7])[0] * (10 ** voltage_scale)
    voltage_L2 = struct.unpack("h", plaintext[7:9])[0] * (10 ** voltage_scale)
    voltage_L3 = struct.unpack("h", plaintext[9:11])[0] * (10 ** voltage_scale)

    current_scale = struct.unpack("b", plaintext[11:12])[0]
    current_L1 = struct.unpack("h", plaintext[12:14])[0] * (10 ** current_scale)
    current_L2 = struct.unpack("h", plaintext[14:16])[0] * (10 ** current_scale)
    current_L3 = struct.unpack("h", plaintext[16:18])[0] * (10 ** current_scale)

    power_scale = struct.unpack("b", plaintext[18:19])[0]
    active_power_plus = struct.unpack("h", plaintext[19:21])[0] * (10 ** power_scale)
    active_power_minus = struct.unpack("h", plaintext[21:23])[0] * (10 ** power_scale)
    reactive_power_plus = struct.unpack("h", plaintext[23:25])[0] * (10 ** power_scale)
    reactive_power_minus = struct.unpack("h", plaintext[25:27])[0] * (10 ** power_scale)

    energy_scale = struct.unpack("b", plaintext[27:28])[0]
    energy_plus = struct.unpack("h", plaintext[28:30])[0] * (10 ** energy_scale)
    energy_minus = struct.unpack("h", plaintext[30:32])[0] * (10 ** energy_scale)

    print(datetime.fromtimestamp(epoch))
    print(f"L1: {voltage_L1}V | {current_L1}A")
    print(f"L2: {voltage_L2}V | {current_L2}A")
    print(f"L3: {voltage_L3}V | {current_L3}A")
    print(f"Power: +{active_power_plus}W | -{active_power_minus}W")
    print(f"Power: +{reactive_power_plus}VA | -{reactive_power_minus}VA")
    print(f"Energy: +{energy_plus}Wh | -{energy_minus}Wh")

def compute_response(challenge, secret_key):
    # Concatenate the challenge and secret_key and compute the hash
    data = challenge + secret_key
    hashed = hashlib.sha256(data).digest()
    return hashed

def get_key(id):
    # todo: lookup key in database based on address and id
    return bytearray.fromhex("b20d7a8c551e3f9a640b2f78d15a0c91")

def derive_key(secret_key, challenge):
    return hmac.new(secret_key, challenge, hashlib.sha256).digest()

def check_response(session_key, packet_counter, response, resp_err, resp_ok):
    failed_response = hmac.new(session_key, packet_counter.to_bytes(8, "little")+resp_err, hashlib.sha256).digest()[0:4]
    success_response = hmac.new(session_key, packet_counter.to_bytes(8, "little")+resp_ok, hashlib.sha256).digest()[0:4]

    if response == failed_response:
        return 0
    elif response == success_response:
        return 1
    return -1

def check_auth_response(session_key, challenge, response, resp_err, resp_ok):
    failed_response = hmac.new(session_key, challenge[0:8]+resp_err, hashlib.sha256).digest()[0:4]
    success_response = hmac.new(session_key, challenge[0:8]+resp_ok, hashlib.sha256).digest()[0:4]

    if response == failed_response:
        return 0
    elif response == success_response:
        return 1
    return -1


def authenticate(client_socket, address, id):
    print("Trying to authenticate")

    auth_packet = AUTH_FRAME+bytearray(id)

    challenge = None
    for i in range(3):
        try:
            client_socket.sendto(auth_packet, address)

            challenge, _ = client_socket.recvfrom(1024)
            break
        except Exception as e:
            print(e)

    if not challenge:
        return (None, None)

    
    session_key = derive_key(get_key(id), challenge)[0:16]
    challenge_response = AUTH_FRAME + compute_response(challenge, session_key)

    packet_counter = struct.unpack("Q", challenge[4:12])[0]


    for i in range(3):
        client_socket.sendto(challenge_response, address)

        try:
            response, _ = client_socket.recvfrom(1024)
            auth_state = check_auth_response(session_key, challenge, response, AUTH_FAILED, AUTH_SUCCESS)

            print(response)

            if auth_state == 1:
                print(f"{address[0]}: Authenticated")
                return (session_key, challenge)
        except Exception as e:
            print(e)
    
    return (None, None)

def send_test_data(client_socket, address, challenge, session_key, data):
    global packet_counter
    global packet_counter_step
    # Replace the following example data with your actual data

    packet_counter+=packet_counter_step
    iv = packet_counter.to_bytes(8, byteorder="little")+challenge[0:4]

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    data_frame = DATA_FRAME + PROTO_VERSION + ciphertext + tag[0:4]
    
    for i in range(3):
        try:
            client_socket.sendto(data_frame, address)

            response, _ = client_socket.recvfrom(1024)
            auth_state = check_response(session_key, packet_counter, response, DATA_FAILED, DATA_SUCCESS)

            if auth_state == 1:
                print("Data sent successfully.")
                break
            else:
                print("Failed to send data.")
        except:
            pass

def request_and_receive_reponse(client_socket, address, challenge, session_key, data):
    global packet_counter
    global packet_counter_step
    # Replace the following example data with your actual data

    packet_counter+=packet_counter_step
    iv = packet_counter.to_bytes(8, byteorder="little")+challenge[0:4]

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    data_frame = bytearray([0x1F, 0]) + ciphertext + tag[0:4]
    
    for i in range(3):
        try:
            client_socket.sendto(data_frame, address)

            

            response, _ = client_socket.recvfrom(1024)

            if response[0] == 0x2F:
                cipher_dec = AES.new(session_key, AES.MODE_GCM, nonce=iv)
                cipher_enc_tag = AES.new(session_key, AES.MODE_GCM, nonce=iv)
                key = cipher_dec.decrypt(response[2:-4])
                _, tag = cipher_enc_tag.encrypt_and_digest(key)

                if response[-4:] == tag[0:4]:
                    return key

        except:
            pass

filename = "Client_Simulator/data/mqtt_messages.json"

def packBinary(data):
    # utc_time = datetime.datetime.strptime(data["timestamp"], "%Y-%m-%dT%H:%M:%S")
    # epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()
    epoch_time = time.time()
    return struct.pack(">IbhhhbhhhbIIbII",
        int(epoch_time),
        -1,
        int(float(data["32.7.0"])*10),
        int(float(data["52.7.0"])*10),
        int(float(data["72.7.0"])*10),
        -2,
        int(float(data["31.7.0"])*100),
        int(float(data["51.7.0"])*100),
        int(float(data["71.7.0"])*100),
        -3,
        int(float(data["1.7.0"])*1000),
        int(float(data["2.7.0"])*1000),
        -3,
        int(float(data["1.8.0"])*1000),
        int(float(data["2.8.0"])*1000),
    )

if __name__ == "__main__":
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # client.settimeout(3)
    server_address = ('127.0.0.1', 4433)  # Replace with the actual server address
    client.connect(server_address)


    client_id = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
    # Replace 'test_id' with the actual ID for authentication
    session_key, challenge = authenticate(client, server_address, client_id)

    print("opening file", filename)
    input = open(filename, 'r')
    print("file opened")
    

    if challenge:
        packet_counter = struct.unpack("Q", challenge[4:12])[0]
        packet_counter_step = packet_counter % 100


        request_and_receive_reponse(client, server_address, challenge, session_key, bytes("key", "utf-8"))


        while True:
            line = input.readline()
            if "message" in line:
                try:
                    line = line.replace('"message": ', '')
                    data_obj = json.loads(line)
                    binary_data = packBinary(data_obj)
                    print("sent data", json.dumps(data_obj))
                    #send_if_new_data(topic, data_obj)
                    send_test_data(client, server_address, challenge, session_key, binary_data)
                except Exception as e:
                    print(e)
                    pass
                time.sleep(5)


