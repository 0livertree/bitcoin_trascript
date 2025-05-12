import socket
import struct
import time
import hashlib

#--------------------------------------------------
# Bitcoin P2P 클라이언트: Version/Verack 핸드쉐이크 + inv 수신 → getdata 요청
#--------------------------------------------------

NODE_PORT = 8333
MAGIC = bytes.fromhex('F9BEB4D9')

#----------------------------------------------------------------------
# 유틸리티 함수
#----------------------------------------------------------------------
def command_to_bytes(command: str) -> bytes:
    """12바이트 command 문자열로 변환"""
    return command.encode('ascii') + b'\x00' * (12 - len(command))

# CompactSize (varint) 파싱
def read_varint(data: bytes, offset: int) -> (int, int):
    first = data[offset]
    offset += 1
    if first < 0xFD:
        return first, offset
    elif first == 0xFD:
        val = struct.unpack('<H', data[offset:offset+2])[0]
        return val, offset+2
    elif first == 0xFE:
        val = struct.unpack('<I', data[offset:offset+4])[0]
        return val, offset+4
    else:
        val = struct.unpack('<Q', data[offset:offset+8])[0]
        return val, offset+8

#----------------------------------------------------------------------
# inv 메시지 파서 및 getdata 메시지 생성
#----------------------------------------------------------------------
def parse_inv(payload: bytes) -> list:
    """
    'inv' 페이로드를 파싱하여 [(type, hash_bytes), ...] 리스트 반환
    해시 bytes는 32바이트 리틀엔디언
    """
    inventory = []
    count, cursor = read_varint(payload, 0)
    print(f'[*] INV contains {count} entries')

    for i in range(count):
        inv_type = struct.unpack('<I', payload[cursor:cursor+4])[0]
        inv_hash = payload[cursor+4:cursor+36]
        cursor += 36
        # human-readable
        type_name = {
            0: 'ERROR',
            1: 'MSG_TX',
            2: 'MSG_BLOCK',
            3: 'MSG_FILTERED_BLOCK',
            4: 'MSG_CMPCT_BLOCK',
            0x40000001: 'MSG_WITNESS_TX',
            0x40000002: 'MSG_WITNESS_BLOCK',
            0x40000003: 'MSG_FILTERED_WITNESS_BLOCK'
        }.get(inv_type, f'UNKNOWN({inv_type})')
        # print(f'    #{i+1}: {type_name} - {inv_hash[::-1].hex()}')
        # if inv_type == 2:
        inventory.append((inv_type, inv_hash))
    return inventory


def make_getdata_message(inventory: list) -> bytes:
    """
    [(type, hash_bytes), ...] 리스트로 'getdata' 메시지 바이트 생성
    """
    count = len(inventory)
    # 1) varint 인코딩
    if count < 0xFD:
        payload = struct.pack('B', count)
    else:
        raise ValueError('Too many inventory items')
    # 2) 각 inv_vect
    for inv_type, inv_hash in inventory:
        payload += struct.pack('<I', inv_type)
        payload += inv_hash
    # 3) 메시지 헤더
    return make_message('getdata', payload)

def make_feefilter_message(min_fee_rate_satoshi_per_kb: int = 1000):
    payload = struct.pack('<Q', min_fee_rate_satoshi_per_kb)
    return make_message('feefilter', payload)

#----------------------------------------------------------------------
# version/verack 페이로드 & 메시지 생성
#----------------------------------------------------------------------
def create_version_payload() -> bytes:
    version = 70015
    services = 0
    timestamp = int(time.time())

    # addr_recv: dummy IPv4-mapped IPv6
    addr_recv_services = 0
    addr_recv_ip = bytes.fromhex('00000000000000000000ffff0a000001')
    addr_recv_port = 8333
    # addr_trans: dummy
    addr_trans_services = 0
    addr_trans_ip = bytes.fromhex('00000000000000000000ffff0a000002')
    addr_trans_port = 8333

    nonce = 0xE6175D8CB35D2E3B
    user_agent = b'\x00'
    start_height = 0
    relay = 0

    payload = struct.pack('<iQQ', version, services, timestamp)
    payload += struct.pack('<Q16sH', addr_recv_services, addr_recv_ip, socket.htons(addr_recv_port))
    payload += struct.pack('<Q16sH', addr_trans_services, addr_trans_ip, socket.htons(addr_trans_port))
    payload += struct.pack('<Q', nonce)
    payload += user_agent
    payload += struct.pack('<i?', start_height, relay)
    return payload


def make_verack_message() -> bytes:
    payload = b''
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    header = MAGIC + command_to_bytes('verack') + struct.pack('<I', 0) + checksum
    return header


def make_message(command: str, payload: bytes) -> bytes:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    header = MAGIC + command_to_bytes(command) + struct.pack('<I', len(payload)) + checksum
    return header + payload

def make_pong_message(nonce):
    payload = struct.pack('<Q', nonce)
    return make_message('pong', payload)

#----------------------------------------------------------------------
# 메시지 파싱 및 핸들러
#----------------------------------------------------------------------
def handle_message(command: str, payload: bytes, sock: socket.socket):
    if command == 'version':
        print('[*] Received version --> sending verack')
        sock.sendall(make_verack_message())
    elif command == 'verack':
        print('[*] Received verack (handshake complete)')
        sock.sendall(make_feefilter_message())
    elif command == 'inv':
        print('[*] Received inv message')
        invs = parse_inv(payload)
        if invs:
            msg = make_getdata_message(invs[:5])
            sock.sendall(msg)
            print(f'[*] Sent getdata for {len(invs[:5])} entries')
    elif command == 'tx':
        print('[*] Received tx message (parsing TBD)')
    elif command == 'block':
        print('[*] Received block message (parsing TBD)')
    elif command == 'ping':
        if len(payload) != 8:
            print('[!] Invalid ping payload length')
            return
        nonce = struct.unpack('<Q', payload)[0]
        print(f'[*] Received ping, nonce: {nonce}')
        pong_msg = make_pong_message(nonce)
        sock.sendall(pong_msg)
        print('[*] Sent pong in response')
    else:
        print(f'[*] Ignored message: {command}')


def parse_messages(data: bytes, sock: socket.socket):
    offset = 0
    while offset + 24 <= len(data):
        magic, cmd_raw, length, checksum = struct.unpack('<4s12sI4s', data[offset:offset+24])

        if magic != MAGIC:
            print(f'[!] Invalid magic bytes at offset {offset}, skipping...')
            offset += 1  # 또는 skip ahead until MAGIC
            continue
        command = cmd_raw.rstrip(b'\x00').decode('ascii')
        if offset + 24 + length > len(data):
            break
        payload = data[offset+24:offset+24+length]
        handle_message(command, payload, sock)
        offset += 24 + length

#----------------------------------------------------------------------
# DNS 시딩
#----------------------------------------------------------------------
def get_bitcoin_node_ip(seed: str) -> str:
    try:
        print(f'[*] DNS seeding: {seed}')
        ip = socket.gethostbyname(seed)
        print(f'[*] Found IP: {ip}')
        return ip
    except Exception as e:
        print(f'[!] DNS seed failed: {e}')
        return ''

#----------------------------------------------------------------------
# Main
#----------------------------------------------------------------------
def connect_and_handshake(ip: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, NODE_PORT))
    print(f'[*] Connected to {ip}:8333')
    # send version
    ver_payload = create_version_payload()
    s.sendall(make_message('version', ver_payload))
    print('[*] Sent version')

    buffer = b''
    while True:
        buffer += s.recv(8192)
        if not buffer:
            print('[!] Connection closed by peer')
            break
        print(f'[*] Received {len(buffer)} bytes')
        while True:
            if len(buffer) < 24:
                break  # 헤더도 못 읽음 → 다음 recv로 대기
            length = struct.unpack('<I', buffer[16:20])[0]
            if len(buffer) < 24 + length:
                break  # 전체 메시지가 안 옴 → 다음 recv로 대기

            msg = buffer[:24+length]
            buffer = buffer[24+length:]  # 처리 후 나머지 유지
            parse_messages(msg, s)
    s.close()
    print('[*] Connection closed')

    

if __name__ == '__main__':
    seeds = [
        'seed.bitcoinstats.com',
        'seed.bitnodes.io',
        'dnsseed.bluematt.me',
        'seed.bitcoin.sipa.be'
    ]
    node_ip = ''
    for sd in seeds:
        node_ip = get_bitcoin_node_ip(sd)
        if node_ip:
            break
    if not node_ip:
        print('[!] Could not get any node IP via DNS. Exiting.')
    else:
        connect_and_handshake(node_ip)
