import socket
import threading
from queue import Queue
from Crypto.Cipher import AES
import hashlib
import hmac
from datetime import datetime
import struct
import os
import paho.mqtt.client as mqtt
import json
import time
import binascii

client_dict = dict()
STATE_UNAUTHORIZED = "unauthorized"
STATE_AUTHSTARTED = "authorization started"
STATE_AUTHORIZED = "authorized"

AUTH_SUCCESS = bytes([0x22])
AUTH_FAILED = bytes([0x11])
DATA_SUCCESS = bytes([0x44])
DATA_FAILED =  bytes([0x33])

DATA_FRAME = 0x0F
AUTH_FRAME = 0xFF
DATA_REQUEST = 0x1F
REQUEST_REPSONSE = 0x2F

DATA_LENGTH = 36
HEADER_LENGTH = 2
FOOTER_LENGTH = 4

client_keys = {
    tuple([0xD4, 0xF9, 0x8D, 0x2D, 0x8F, 0x44]): bytearray.fromhex("e487c2b1a3d197d8d9915db06b758199"),
    tuple([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]): bytearray.fromhex("b20d7a8c551e3f9a640b2f78d15a0c91"),
    tuple([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]): bytearray.fromhex("a3f8e2d147c690b4d6a9012f874b3c5a")
    }

def generate_challenge():
    return bytearray(os.urandom(16))  # Generate a random challenge (16 bytes)

def compute_response(challenge, secret_key):
    # Concatenate the challenge and secret_key and compute the hash
    data = challenge + secret_key
    hashed = hashlib.sha256(data).digest()
    return hashed


def get_key(client_id):
    # todo: lookup key in database based on address and id
    try:
        return client_keys[client_id]
    except:
        return None

def derive_key(secret_key, challenge):
    return hmac.new(secret_key, challenge, hashlib.sha256).digest()

def get_meter_key():
    return bytes([0x32, 0x69, 0x31, 0x63, 0x79, 0x79, 0x45, 0x6C, 0x59, 0x37, 0x34, 0x44, 0x73, 0x6D, 0x33, 0x75])


def handle_client(server_socket, client_dict, client_address, data):

    print(f'{client_address}: {client_dict[client_address]["state"]}')
    
    if data[0] == AUTH_FRAME:
        if client_dict[client_address]["state"] == STATE_AUTHORIZED:
            client_dict[client_address]["state"] = STATE_UNAUTHORIZED
        if client_dict[client_address]["state"] == STATE_UNAUTHORIZED:
            if len(data)<7:
                return
            client_id = tuple(data[1:7])
            key = get_key(client_id)
            
            if not key:
                return
            challenge = generate_challenge()
            server_socket.sendto(challenge, client_address)
            client_dict[client_address]["state"] = STATE_AUTHSTARTED
            client_dict[client_address]["id"] = client_id
            client_dict[client_address]["key"] = key
            client_dict[client_address]["challenge"] = challenge
            client_dict[client_address]["packet_counter"] = struct.unpack("Q", challenge[4:12])[0]
            client_dict[client_address]["counter_offset"] = client_dict[client_address]["packet_counter"] % 100
             

        elif client_dict[client_address]["state"] == STATE_AUTHSTARTED:
            # cipher = AES.new(client_dict[client_address]["key"], AES.MODE_GCM, nonce=bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]))
            session_key = derive_key(client_dict[client_address]["key"], client_dict[client_address]["challenge"])[0:16]
            client_dict[client_address]["session_key"] = session_key
            expected_response = compute_response(client_dict[client_address]["challenge"], client_dict[client_address]["session_key"])
            print("Sessionkey:", client_dict[client_address]["session_key"].hex())
            print("Challenge:", client_dict[client_address]["challenge"].hex())
            if data[1:] == expected_response:
                client_dict[client_address]["state"] = STATE_AUTHORIZED   
                
                response_data = hmac.new(client_dict[client_address]["session_key"], client_dict[client_address]["challenge"][0:8]+AUTH_SUCCESS, hashlib.sha256).digest()[0:4]
                server_socket.sendto(response_data, client_address)
                print("Response:", response_data.hex())
            else:
                client_dict[client_address]["state"] = STATE_UNAUTHORIZED

                response_data = hmac.new(client_dict[client_address]["session_key"], client_dict[client_address]["challenge"][0:8]+AUTH_FAILED, hashlib.sha256).digest()[0:4]
                server_socket.sendto(response_data, client_address)
    elif data[0] == DATA_FRAME:
        if client_dict[client_address]["state"] == STATE_AUTHORIZED:
            client_dict[client_address]["packet_counter"]+=client_dict[client_address]["counter_offset"]
            version = data[1]
            if version == 0:
                iv = client_dict[client_address]["packet_counter"].to_bytes(8, byteorder="little")+client_dict[client_address]["challenge"][0:4]

                cipher = AES.new(client_dict[client_address]["session_key"], AES.MODE_GCM, nonce=iv)
                cipher_dec = AES.new(client_dict[client_address]["session_key"], AES.MODE_GCM, nonce=iv)

                plaintext = cipher.decrypt(data[HEADER_LENGTH:HEADER_LENGTH+DATA_LENGTH])

                _, tag = cipher_dec.encrypt_and_digest(plaintext)

                if tag[0:4] != data[HEADER_LENGTH+DATA_LENGTH:]: 
                    client_dict[client_address]["state"] =STATE_UNAUTHORIZED
                    response_data = hmac.new(client_dict[client_address]["session_key"], client_dict[client_address]["packet_counter"].to_bytes(8, "little")+DATA_FAILED, hashlib.sha256).digest()[0:4]

                    server_socket.sendto(response_data, client_address)

                    print("Data response tag failed", response_data.hex())
                    return

                if len(plaintext)==DATA_LENGTH:
                    try:
                        epoch = struct.unpack(">I", plaintext[0:4])[0]

                        voltage_scale = struct.unpack("b", plaintext[4:5])[0]
                        voltage_L1 = struct.unpack(">h", plaintext[5:7])[0] * (10 ** voltage_scale)
                        voltage_L2 = struct.unpack(">h", plaintext[7:9])[0] * (10 ** voltage_scale)
                        voltage_L3 = struct.unpack(">h", plaintext[9:11])[0] * (10 ** voltage_scale)

                        current_scale = struct.unpack("b", plaintext[11:12])[0]
                        current_L1 = struct.unpack(">h", plaintext[12:14])[0] * (10 ** current_scale)
                        current_L2 = struct.unpack(">h", plaintext[14:16])[0] * (10 ** current_scale)
                        current_L3 = struct.unpack(">h", plaintext[16:18])[0] * (10 ** current_scale)

                        power_scale = struct.unpack("b", plaintext[18:19])[0]
                        active_power_plus = struct.unpack(">I", plaintext[19:23])[0] * (10 ** power_scale)
                        active_power_minus = struct.unpack(">I", plaintext[23:27])[0] * (10 ** power_scale)

                        energy_scale = struct.unpack("b", plaintext[27:28])[0]
                        energy_plus = struct.unpack(">I", plaintext[28:32])[0] * (10 ** energy_scale)
                        energy_minus = struct.unpack(">I", plaintext[32:36])[0] * (10 ** energy_scale)

                        print(f"\nData from Client: {client_address}")
                        print(datetime.fromtimestamp(epoch))
                        print(f"L1: {voltage_L1:.1f}V | {current_L1:.2f}A")
                        print(f"L2: {voltage_L2:.1f}V | {current_L2:.2f}A")
                        print(f"L3: {voltage_L3:.1f}V | {current_L3:.2f}A")
                        print(f"Power: +{active_power_plus:.3f}W | -{active_power_minus:.3f}W")
                        # print(f"Power: +{reactive_power_plus:.3f}VA | -{reactive_power_minus:.3f}VA")
                        print(f"Energy: +{energy_plus:.3f}Wh | -{energy_minus:.3f}Wh")


                        mqtt_data = {
                            "measurementId": {
                                "deviceId": binascii.hexlify(bytes(client_dict[client_address]["id"])).decode('utf-8'), 
                                "timestamp": datetime.fromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M:%S")
                            },
                            "voltageL1V": voltage_L1,
                            "voltageL2V": voltage_L2,
                            "voltageL3V": voltage_L3,
                            "currentL1A": current_L1,
                            "currentL2A": current_L2,
                            "currentL3A": current_L3,
                            "instantaneousActivePowerPlusW": active_power_plus,
                            "instantaneousActivePowerMinusW": active_power_minus,
                            "totalEnergyConsumedWh": energy_plus,
                            "totalEnergyDeliveredWh": energy_minus
                        }

                        mqtt_data_string = json.dumps(mqtt_data)
                        client.publish("simulator", mqtt_data_string)

                        response_data = hmac.new(client_dict[client_address]["session_key"], client_dict[client_address]["packet_counter"].to_bytes(8, "little")+DATA_SUCCESS, hashlib.sha256).digest()[0:4]
                        server_socket.sendto(response_data, client_address)
                    except Exception as e:
                        response_data = hmac.new(client_dict[client_address]["session_key"], client_dict[client_address]["packet_counter"].to_bytes(8, "little")+DATA_FAILED, hashlib.sha256).digest()[0:4]
                        server_socket.sendto(response_data, client_address)
                        print(e)

    elif data[0] == DATA_REQUEST:
        if client_dict[client_address]["state"] == STATE_AUTHORIZED:
            client_dict[client_address]["packet_counter"]+=client_dict[client_address]["counter_offset"]
            version = data[1]
            if version == 0:
                iv = client_dict[client_address]["packet_counter"].to_bytes(8, byteorder="little")+client_dict[client_address]["challenge"][0:4]

                cipher = AES.new(client_dict[client_address]["session_key"], AES.MODE_GCM, nonce=iv)
                cipher_dec = AES.new(client_dict[client_address]["session_key"], AES.MODE_GCM, nonce=iv)
                
                print("request data:", data.hex())

                plaintext = cipher.decrypt(data[HEADER_LENGTH:-4])

                _, tag = cipher_dec.encrypt_and_digest(plaintext)

                if tag[0:4] != data[-4:]: 
                    print("Data response tag failed", response_data.hex())
                    return

                if plaintext.decode("utf-8")=="key":
                    try:
                        cipher_enc_response = AES.new(client_dict[client_address]["session_key"], AES.MODE_GCM, nonce=iv)
                        encrypted_key, key_tag = cipher_enc_response.encrypt_and_digest(get_meter_key())
                        request_response_frame = bytearray([REQUEST_REPSONSE, 0])+encrypted_key+key_tag[0:4]
                        server_socket.sendto(request_response_frame, client_address)
                    except Exception as e:
                        print(e)

if __name__ == "__main__":

    client = mqtt.Client()
    client.connect("broker", 1883)

    client.loop_start()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 4433))

    dataQueue = Queue()

    while True:
        data, client_address = server_socket.recvfrom(1024)
        if client_address not in client_dict:
            client_dict[client_address] = {
                "state": STATE_UNAUTHORIZED,
            }

        client_thread = threading.Thread(target=handle_client, args=(server_socket, client_dict, client_address, data))
        client_thread.start()

        


    client.loop_stop()
