import sys
import qrcode
from PyQt5.QtGui import QPixmap
import os
import requests
from flask import Flask, jsonify, request, send_file
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QPushButton, QWidget, QScrollArea, QLineEdit
import socket
from flask import Flask, jsonify, request
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QPixmap
from io import BytesIO
import requests
import random
import numpy as np
from PyQt5.QtGui import QClipboard
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QLabel, QPushButton, QVBoxLayout
from PyQt5.QtGui import QClipboard
from PyQt5.QtGui import QPixmap, QClipboard
from flask import Flask, jsonify, request
import pyopencl as cl
import numpy as np
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QLabel, QVBoxLayout
import pyopencl as cl
import numpy as np

app = Flask(__name__)

def get_local_ip():
    """Retorna o endereço IP local do cliente."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Tente se conectar a um endereço externo para obter o IP local
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip

@app.route('/api/local_ip', methods=['GET'])
def local_ip():
    """Retorna o endereço IP local do servidor."""
    ip = get_local_ip()
    return jsonify({'local_ip': ip})
    
def set_node_url(self):
    self.node_url = self.node_input.text()
    if self.node_url:
        self.create_wallet_btn.setEnabled(True)
    else:
        QtWidgets.QMessageBox.warning(self, "Erro", "Por favor, insira um endereço de nó válido.")

def random_qubit():
    """Gera um qubit aleatório em formato de vetor."""
    a = random.random()
    b = random.random()
    norm = np.sqrt(a**2 + b**2)
    return [a / norm, b / norm]

def generate_qubits(num_qubits):
    """Gera uma lista de qubits aleatórios."""
    return [random_qubit() for _ in range(num_qubits)]

@app.route('/api/wallet/create', methods=['GET'])
def create_wallet():
    # Simula a criação de uma carteira
    wallet_info = {
        'address': 'endereco_da_carteira_exemplo',
        'private_key': 'chave_privada_exemplo'
    }
    return jsonify(wallet_info), 201

@app.route('/api/balance/<address>', methods=['GET'])
def check_balance(address):
    # Simula a verificação de saldo
    balance_info = {
        'balance': 100.0  # Valor de exemplo
    }
    return jsonify(balance_info), 200

@app.route('/api/mine', methods=['GET'])
def mine():
    # Simula a mineração
    block_info = {
        'index': 1,
        'previous_hash': 'hash_anterior_exemplo'
    }
    return jsonify(block_info), 200

@app.route('/api/qrcode', methods=['POST'])
def generate_qr_code():
    qr_data = request.json.get('data', '')
    qr = qrcode.make(qr_data)
    qr_image = BytesIO()
    qr.save(qr_image, 'PNG')
    qr_image.seek(0)
    return send_file(qr_image, mimetype='image/png')

import time
import threading
import hashlib
import requests
from tqdm import tqdm
from PyQt5 import QtCore
import pyopencl as cl
import psutil
from threading import Lock

class MinerThread(QtCore.QThread):
    block_mined = QtCore.pyqtSignal(int, str)

    mining_lock = Lock()  # 🔒 Lock compartilhado entre instâncias da thread

    def __init__(self):
        super().__init__()
        self.active = False
        self.miner_address = ''
        self.retry_count = 0

    def run(self):
        while True:
            if self.active:
                # 🔐 Tenta adquirir o lock antes de minerar
                if MinerThread.mining_lock.acquire(blocking=False):
                    try:
                        url = f'http://127.0.0.1/mine?miner={self.miner_address}'
                        response = requests.get(url)

                        if response.status_code == 200:
                            self.exibir_animacao_mineracao()

                            block_info = response.json()
                            print(f"Bloco minerado com sucesso!")
                            print(f"Índice do Bloco: {block_info['index']}")
                            print(f"Hash do Bloco Anterior: {block_info['previous_hash']}")
                            print(f"Dificuldade: {block_info['difficulty']}")
                            print(f"Prova: {block_info['proof']}")
                            print(f"Transações: {block_info['transactions']}")

                            self.block_mined.emit(block_info['index'], block_info['previous_hash'])

                            self.start_local_mining_threads(block_info)
                            self.retry_count = 0
                        else:
                            print(f"Erro ao minerar: {response.status_code}")
                            self.retry_count += 1
                            self.handle_retry_delay()
                    except requests.exceptions.RequestException as e:
                        print(f"Erro na conexão: {e}")
                        self.retry_count += 1
                        self.handle_retry_delay()
                    finally:
                        # 🔓 Libera o lock após mineração (ou erro)
                        MinerThread.mining_lock.release()
                else:
                    # Outro processo já está minerando
                    time.sleep(0.5)
            else:
                time.sleep(0.1)


    def handle_retry_delay(self):
        if self.retry_count > 5:
            print("Muitas tentativas falhadas, aguardando 30 segundos antes de tentar novamente...")
            time.sleep(30)
        else:
            time.sleep(1)

    def exibir_animacao_mineracao(self):
        passos = 10  # duração da animação da barra de progresso
        for _ in tqdm(range(passos), desc="⛏️ Minerando... 💰"):
            time.sleep(0.1)

    def start_local_mining_threads(self, block_info):
        cpu_thread = threading.Thread(target=self.mine_with_cpu, args=(block_info,))
        cpu_thread.start()

        if self.is_gpu_available():
            gpu_thread = threading.Thread(target=self.mine_with_gpu, args=(block_info,))
            gpu_thread.start()

    def is_gpu_available(self):
        try:
            platforms = cl.get_platforms()
            for platform in platforms:
                devices = platform.get_devices(device_type=cl.device_type.GPU)
                if devices:
                    return True
        except Exception as e:
            print(f"Erro ao detectar GPU: {e}")
        return False

    def mine_with_gpu(self, block_info):
        try:
            transactions = block_info['transactions']
            previous_hash = block_info['previous_hash']

            block_data = previous_hash + str(transactions)
            block_size = 64  # SHA-256 output size

            platforms = cl.get_platforms()
            platform = platforms[0]
            devices = platform.get_devices(device_type=cl.device_type.GPU)
            if not devices:
                raise Exception("Nenhum dispositivo GPU encontrado.")
            device = devices[0]
            context = cl.Context([device])
            queue = cl.CommandQueue(context, device)

            program_src = """
            __kernel void mine_block(__global const char* block_data, __global char* hash_result) {
                int id = get_global_id(0);
                hash_result[id] = block_data[id];
            }
            """
            program = cl.Program(context, program_src).build()

            block_data_buffer = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=block_data.encode('utf-8'))
            hash_buffer = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, block_size)

            program.mine_block(queue, (block_size,), None, block_data_buffer, hash_buffer)

            result = bytearray(block_size)
            cl.enqueue_copy(queue, result, hash_buffer).wait()

            hash_value = result.decode('utf-8', errors='ignore')
            print(f"Bloco minerado com sucesso usando GPU!")
            print(f"Hash Minerado: {hash_value}")

            self.block_mined.emit(block_info['index'], hash_value)
            self.show_gpu_details(device)

        except Exception as e:
            print(f"Erro ao minerar com GPU: {e}")

    def mine_with_cpu(self, block_info):
        transactions = block_info['transactions']
        hash_value = self.mine_block(block_info['previous_hash'], transactions)
        print(f"Bloco minerado com sucesso usando CPU!")
        print(f"Hash Minerado: {hash_value}")
        self.block_mined.emit(block_info['index'], hash_value)
        self.show_cpu_details()

    def mine_block(self, previous_hash, transactions):
        block_data = previous_hash + str(transactions)
        return hashlib.sha256(block_data.encode('utf-8')).hexdigest()

    def start_mining(self, miner_address):
        self.miner_address = miner_address
        self.active = True
        if not self.isRunning():
            self.start()

    def stop_mining(self):
        self.active = False

    def show_gpu_details(self, device):
        try:
            print("Detalhes da GPU:")
            print(f"Nome: {device.get_info(cl.device_info.NAME)}")
            print(f"Número de Unidades de Computação: {device.get_info(cl.device_info.MAX_COMPUTE_UNITS)}")
            print(f"Frequência Máxima (MHz): {device.get_info(cl.device_info.MAX_CLOCK_FREQUENCY)} MHz")
            print(f"Versão do OpenCL: {device.get_info(cl.device_info.VERSION)}")
            print(f"Tipo de dispositivo: {device.get_info(cl.device_info.TYPE)}")
            print(f"Driver: {device.get_info(cl.device_info.DRIVER_VERSION)}")
            print(f"Tamanho Máximo de Work Group: {device.get_info(cl.device_info.MAX_WORK_GROUP_SIZE)}")
            print(f"Tamanhos Máximos de Work Item por dimensão (X, Y, Z): {device.get_info(cl.device_info.MAX_WORK_ITEM_SIZES)}")
            print(f"Tamanho Máximo de Memória de Work Group: {device.get_info(cl.device_info.MAX_MEM_ALLOC_SIZE) // (1024 ** 2)} MB")
        except Exception as e:
            print(f"Erro ao obter detalhes da GPU: {e}")

    def show_cpu_details(self):
        print("Detalhes da CPU:")
        print(f"Número de núcleos: {psutil.cpu_count(logical=False)}")
        print(f"Número de threads: {psutil.cpu_count(logical=True)}")
        freq = psutil.cpu_freq()
        if freq:
            print(f"Frequência Atual: {freq.current} MHz")
        print(f"Uso Total da CPU: {psutil.cpu_percent(interval=1)}%")
        print(f"Uso por Núcleo: {psutil.cpu_percent(interval=1, percpu=True)}")

import pyopencl as cl
import numpy as np
import hashlib

# Configuração OpenCL
platform = cl.get_platforms()[0]
device = platform.get_devices()[0]
ctx = cl.Context([device])
queue = cl.CommandQueue(ctx)

# Carrega o kernel OpenCL
with open("sha256.cl", "r") as f:
    kernel_code = f.read()

program = cl.Program(ctx, kernel_code).build()

# Dados de entrada
input_str = b"orbycar-miner"
input_len = np.uint32(len(input_str))
difficulty = np.uint32(26)  # ajuste a dificuldade aqui

# Buffers
mf = cl.mem_flags
input_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=input_str)
found_nonce_buf = cl.Buffer(ctx, mf.WRITE_ONLY, size=4)
found_flag_buf = cl.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=np.array([0], dtype=np.int32))

# Parâmetros
worksize = 1024 * 64  # Tamanho do grupo de trabalho
start_nonce = 0


while True:
    # Reinicia o flag encontrado
    cl.enqueue_fill_buffer(queue, found_flag_buf, np.int32(0), 0, 4)

    # Executa o kernel
    program.sha256_kernel(queue, (worksize,), None,
                          input_buf, input_len, found_nonce_buf, found_flag_buf,
                          np.uint32(start_nonce), difficulty)

    found = np.empty(1, dtype=np.int32)
    cl.enqueue_copy(queue, found, found_flag_buf)
    queue.finish()

    if found[0] == 1:
        result_nonce = np.empty(1, dtype=np.uint32)
        cl.enqueue_copy(queue, result_nonce, found_nonce_buf)

        # Calcula o hash final com hashlib para confirmar
        nonce_bytes = int(result_nonce[0]).to_bytes(4, byteorder='big')
        final_hash = hashlib.sha256(input_str + nonce_bytes).hexdigest()

        print(f"✅ Nonce encontrado: {result_nonce[0]}")
        print(f"🧠 Hash: {final_hash}")
        break

    start_nonce += worksize

def mine_block_proof_of_work(previous_hash, transactions, difficulty):
    prefix = '0' * difficulty
    nonce = 0
    while True:
        text = previous_hash + str(transactions) + str(nonce)
        hash_result = hashlib.sha256(text.encode()).hexdigest()
        if hash_result.startswith(prefix):
            return nonce, hash_result
        nonce += 1


class QrCodeViewer(QtWidgets.QWidget):
    def __init__(self, qr_data):
        super().__init__()
        self.setWindowTitle("QR Code Ampliado")
        self.setGeometry(200, 200, 400, 400)

        layout = QVBoxLayout()

        # Gera o QR Code com o dado recebido
        qr = qrcode.make(qr_data)
        qr_image = BytesIO()
        qr.save(qr_image, 'PNG')
        qr_image.seek(0)

        pixmap = QPixmap()
        pixmap.loadFromData(qr_image.getvalue())
        
        # Cria um QLabel para exibir o QR Code
        qr_code_label = QLabel(self)
        

        
class CryptoClient(QWidget):
    def __init__(self):
        super().__init__()
        self.node_url = None
        self.valid_node_url = 'http://127.0.0.1'
        self.initUI()
        self.miner_thread = MinerThread()
        self.miner_thread.block_mined.connect(self.update_mining_status)
        self.wallet_created = False

    def initUI(self):
        self.setWindowTitle('Cliente Descentralizado de Criptomoeda Bitcoin3.0')
        self.setGeometry(100, 100, 400, 600)

        layout = QVBoxLayout()

        # Caminho relativo para imagem embutida
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        image_path = os.path.join(base_path, 'bitcoin-3-btc3-coin-logo.png')

        image_label = QLabel(self)
        pixmap = QPixmap(image_path)
        image_label.setPixmap(pixmap)
        image_label.setScaledContents(True)
        image_label.setFixedHeight(200)

        layout.addWidget(image_label)
        self.setLayout(layout)

        # Node URL input field
        self.node_input = QLineEdit(self)
        self.node_input.setPlaceholderText('Digite o endereço do nó (Ex: http://127.0.0.1')
        layout.addWidget(self.node_input)

        # Button to confirm the node URL
        self.set_node_btn = QPushButton('Confirmar Nó', self)
        self.set_node_btn.clicked.connect(self.set_node_url)
        layout.addWidget(self.set_node_btn)

        # Functionality buttons, initially disabled
        self.create_wallet_btn = QPushButton('Criar Carteira', self)
        self.create_wallet_btn.clicked.connect(self.create_wallet)
        self.create_wallet_btn.setEnabled(False)
        layout.addWidget(self.create_wallet_btn)

        self.wallet_info = QLabel('', self)
        layout.addWidget(self.wallet_info)

        self.copy_private_key_btn = QPushButton('Copiar Chave Privada', self)
        self.copy_private_key_btn.clicked.connect(self.copy_private_key)
        self.copy_private_key_btn.setEnabled(False)
        layout.addWidget(self.copy_private_key_btn)
        
        self.copy_address_btn = QPushButton('Copiar Endereço', self)
        self.copy_address_btn.clicked.connect(self.copy_address)
        self.copy_address_btn.setEnabled(False)  # Corrected: this should be disabled initially
        layout.addWidget(self.copy_address_btn)

        self.check_balance_btn = QPushButton('Ver Saldo', self)
        self.check_balance_btn.clicked.connect(self.check_balance)
        self.check_balance_btn.setEnabled(False)
        layout.addWidget(self.check_balance_btn)

        self.address_input = QLineEdit(self)
        self.address_input.setPlaceholderText('Endereço da Carteira (Existente)')
        layout.addWidget(self.address_input)

        self.balance_label = QLabel('Saldo: 0', self)
        layout.addWidget(self.balance_label)

        self.send_amount_input = QLineEdit(self)
        self.send_amount_input.setPlaceholderText('Valor a enviar')
        layout.addWidget(self.send_amount_input)

        self.sender_input = QLineEdit(self)
        self.sender_input.setPlaceholderText('Endereço da Carteira que Envia')
        layout.addWidget(self.sender_input)

        self.recipient_input = QLineEdit(self)
        self.recipient_input.setPlaceholderText('Endereço do Destinatário')
        layout.addWidget(self.recipient_input)

        self.private_key_input = QLineEdit(self)
        self.private_key_input.setPlaceholderText('Chave Privada')
        layout.addWidget(self.private_key_input)

        self.send_btn = QPushButton('Enviar Saldo', self)
        self.send_btn.clicked.connect(self.send_balance)
        self.send_btn.setEnabled(False)  # Initially disabled
        layout.addWidget(self.send_btn)

        self.start_mining_btn = QPushButton('Iniciar Mineração com Endereço Existente', self)
        self.start_mining_btn.clicked.connect(self.start_mining_if_wallet_exists)
        self.start_mining_btn.setEnabled(False)  # Initially disabled
        layout.addWidget(self.start_mining_btn)

        self.mining_status_label = QLabel('Minerando... Bloco: Nenhum', self)
        layout.addWidget(self.mining_status_label)

        self.qr_code_label = QLabel(self)
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area_content = QWidget()
        self.scroll_area_layout = QVBoxLayout(self.scroll_area_content)
        self.scroll_area_layout.addWidget(self.qr_code_label)
        self.scroll_area.setWidget(self.scroll_area_content)
        layout.addWidget(self.scroll_area)

        self.maximize_qr_btn = QPushButton('Ampliar QR Code', self)
        self.maximize_qr_btn.clicked.connect(self.maximize_qr_code)
        self.maximize_qr_btn.setEnabled(False)  # Initially disabled
        layout.addWidget(self.maximize_qr_btn)

        self.local_api_btn = QPushButton('Local API', self)
        self.local_api_btn.clicked.connect(self.show_local_api_options)
        layout.addWidget(self.local_api_btn)

        self.setLayout(layout)

    def set_node_url(self):
        """Defines the node URL and activates buttons if valid."""
        url = self.node_input.text().strip()  # Remove whitespace

        # Check if the URL is empty
        if not url:
            QtWidgets.QMessageBox.warning(self, 'URL do Nó', 'Por favor, insira uma URL válida do nó.')
            return
    
        # Check if the entered URL is the valid URL
        if url == self.valid_node_url:
            self.node_url = url  # Store the node URL
            # Enable functionality buttons
            self.create_wallet_btn.setEnabled(True)
            self.copy_private_key_btn.setEnabled(True)
            self.copy_address_btn.setEnabled(True)  # Enable this button
            self.check_balance_btn.setEnabled(True)
            self.send_btn.setEnabled(True)
            self.start_mining_btn.setEnabled(True)
            self.maximize_qr_btn.setEnabled(True)
            QtWidgets.QMessageBox.information(self, "Sucesso", "URL do nó confirmada com sucesso.")
        else:
            QtWidgets.QMessageBox.warning(self, "Erro", "URL do nó inválida. Verifique e tente novamente.")
            # Disable functionality buttons if the URL is incorrect
            self.create_wallet_btn.setEnabled(False)
            self.copy_private_key_btn.setEnabled(False)
            self.copy_address_btn.setEnabled(False)  # Also disable this button
            self.check_balance_btn.setEnabled(False)
            self.send_btn.setEnabled(False)
            self.start_mining_btn.setEnabled(False)
            self.maximize_qr_btn.setEnabled(False)

            
    def activate_buttons(self):
        """Ativa os botões de funcionalidade."""
        self.create_wallet_btn.setEnabled(True)
        self.copy_private_key_btn.setEnabled(True)
        self.check_balance_btn.setEnabled(True)
        # Ativa outros botões conforme necessário

    def create_wallet(self):
        """Cria uma nova carteira usando a URL do nó."""
        if not self.node_url:
            self.display_error('Por favor, defina a URL do nó primeiro.')
            return

        try:
            response = requests.get(f'{self.node_url}/wallet/create', timeout=5)
            if response.status_code == 201:
                wallet_info = response.json()
                self.wallet_info.setText(f"Endereço: {wallet_info['address']}\nChave Privada: {wallet_info['private_key']}")
            else:
                self.display_error("Erro ao criar a carteira.")
        except requests.exceptions.RequestException as e:
            self.display_error(f"Erro de conexão: {e}")

    def check_balance(self):
        """Consulta o saldo de uma carteira na URL do nó especificado."""
        if not self.node_url:
            self.display_error('Por favor, defina a URL do nó primeiro.')
            return

        address = self.address_input.text().strip()
        if not address:
            self.balance_label.setText('Por favor, insira um endereço de carteira.')
            return

        try:
            response = requests.get(f'{self.node_url}/balance/{address}')
            if response.status_code == 200:
                balance_info = response.json()
                self.balance_label.setText(f'Saldo: {balance_info["balance"]}')
            else:
                self.balance_label.setText('Erro ao verificar o saldo.')
        except Exception as e:
            self.balance_label.setText(f'Erro: {e}')

    def display_error(self, message):
        """Exibe uma mensagem de erro."""
        QtWidgets.QMessageBox.critical(self, 'Erro', message)

    def show_local_api_options(self):
        options = [
            'http://127.0.0.1/contract/carteira/external-transactions',
            'http://127.0.0.1/balance/<address>',
            'http://127.0.0.1/transactions/new',
            'http://127.0.0.1/chain',
            'http://127.0.0.1/transfer',
            'http://127.0.0.1/wallet/create',
            'http://127.0.0.1/mine'
        ]
    
        # Cria uma janela para mostrar as opções de API
        options_dialog = QtWidgets.QDialog(self)
        options_dialog.setWindowTitle('Opções de API Local')
        options_layout = QVBoxLayout()

        # Adiciona as URLs como labels
        for option in options:
            label = QLabel(option)
            options_layout.addWidget(label)

        # Cria um botão para copiar
        copy_button = QPushButton('Copiar URLs', self)
        copy_button.clicked.connect(lambda: self.copy_to_clipboard(options))
        options_layout.addWidget(copy_button)

        options_dialog.setLayout(options_layout)
        options_dialog.exec_()

    def copy_to_clipboard(self, options):
        # Junte as opções em uma única string separada por nova linha
        text_to_copy = "\n".join(options)
        # Acessa o clipboard
        clipboard = QtWidgets.QApplication.clipboard()  # Obter a instância do clipboard da aplicação
        # Copia o texto para o clipboard
        clipboard.setText(text_to_copy)

    def create_wallet(self):
        try:
            response = requests.get('http://127.0.0.1/wallet/create', timeout=5)
            if response.status_code == 201:
                wallet_info = response.json()
                self.wallet_info.setText(f"Endereço: {wallet_info['address']}\nChave Privada: {wallet_info['private_key']}")
                self.start_mining(wallet_info['address'])
                self.maximize_qr_code()  # Gera o QR Code assim que a carteira é criada
            else:
                # Se o status code for diferente de 201
                self.wallet_info.setText("Erro ao criar a carteira. Tente novamente mais tarde.")
        except requests.ConnectionError:
            # Oculta a URL e exibe mensagem amigável
            self.wallet_info.setText("Erro de conexão.  está indisponível no momento.")
        except requests.Timeout:
            self.wallet_info.setText("O tempo de resposta  esgotou. Tente novamente mais tarde.")
        except Exception as e:
            # Lida com qualquer outro tipo de erro
            self.wallet_info.setText(f"Erro inesperado: {e}")

    def start_mining_if_wallet_exists(self):
        miner_address = self.address_input.text().strip()
        if miner_address:  # Verifica se o endereço da carteira foi fornecido
            self.start_mining(miner_address)
        else:
            self.mining_status_label.setText('Por favor, insira um endereço de carteira existente.')

    def start_new_mining(self):
        if self.wallet_created:
            miner_address = self.extract_address()
            if miner_address:
                self.start_mining(miner_address)
        else:
            self.mining_status_label.setText('Por favor, crie uma carteira primeiro.')

    def start_mining(self, miner_address):
        self.miner_thread.start_mining(miner_address)

    def update_mining_status(self, block_index, previous_hash):
        print(f'Atualizando status da mineração: Bloco {block_index}, Hash anterior: {previous_hash}')  # Adicione isso
        self.mining_status_label.setText(f'Minerando... Bloco: {block_index} (Hash anterior: {previous_hash})')
        qr_data = f"Bloco: {block_index}\nHash Anterior: {previous_hash}"
        self.display_qr_code(qr_data)

    def display_qr_code(self, qr_data):
        qr = qrcode.make(qr_data)
        qr_image = BytesIO()
        qr.save(qr_image, 'PNG')
        qr_image.seek(0)

        pixmap = QPixmap()
        pixmap.loadFromData(qr_image.getvalue())
        self.qr_code_label.setPixmap(pixmap.scaled(200, 200, QtCore.Qt.KeepAspectRatio))

    def copy_private_key(self):
        private_key = self.extract_private_key()
        if private_key:
            QtWidgets.QApplication.clipboard().setText(private_key)

    def copy_address(self):
        address = self.extract_address()
        if address:
            QtWidgets.QApplication.clipboard().setText(address)

    def extract_private_key(self):
        try:
            return self.wallet_info.text().split('\n')[1].split(': ')[1]
        except IndexError:
            return None

    def extract_address(self):
        try:
            return self.wallet_info.text().split('\n')[0].split(': ')[1]
        except IndexError:
            return None

    def check_balance(self):
        address = self.address_input.text().strip()
        if not address:
            self.balance_label.setText('Por favor, insira um endereço de carteira.')
            return

        try:
            response = requests.get(f'http://127.0.0.1/balance/{address}')
            if response.status_code == 200:
                balance_info = response.json()
                self.balance_label.setText(f'Saldo: {balance_info["balance"]}')
            else:
                self.balance_label.setText('Erro ao verificar o saldo.')
        except Exception as e:
            self.balance_label.setText(f'Erro: {e}')

    def send_balance(self):
        # Extrair informações dos campos
        sender_address = self.sender_input.text().strip()  # Endereço da carteira que envia
        private_key = self.private_key_input.text().strip()  # Chave privada do remetente
        recipient = self.recipient_input.text().strip()  # Endereço do destinatário
        amount = self.send_amount_input.text().strip()  # Valor a ser enviado

        # Validações
        if not sender_address:
            self.balance_label.setText('Por favor, insira o endereço da carteira que envia.')
            return

        if not private_key:
            self.balance_label.setText('Por favor, insira a chave privada do remetente.')
            return

        if not recipient:
            self.balance_label.setText('Por favor, insira o endereço da carteira do destinatário.')
            return

        if not amount:
            self.balance_label.setText('Por favor, insira um valor para a transação.')
            return

        try:
            amount = float(amount)
            if amount <= 0:
                self.balance_label.setText('O valor deve ser positivo.')
                return
        except ValueError:
            self.balance_label.setText('Por favor, insira um valor numérico válido.')
            return

        # Preparar os dados da transação
        transaction_data = {
            'private_key': private_key,
            'sender': sender_address,  # Adicionado para indicar a carteira de envio
            'recipient': recipient,
            'amount': amount
        }

        # Comunicação com o servidor
        try:
            response = requests.post(' http://127.0.0.1/transfer', json=transaction_data)

            if response.status_code == 200:
                transaction_info = response.json()  # Captura a resposta JSON
                self.balance_label.setText(f'Transação realizada com sucesso! {transaction_info["message"]}')
            else:
                self.balance_label.setText(f'Erro ao enviar transação: {response.status_code} - {response.text}')
        except requests.exceptions.RequestException as e:
            self.balance_label.setText(f'Erro ao se conectar ao servidor: {e}')

    def start_mining(self, miner_address):
        self.miner_thread.start_mining(miner_address)
        self.mining_status_label.setText('Minerando...')

    def stop_mining(self):
        self.miner_thread.stop_mining()

    def update_mining_status(self, block_index, previous_hash):
        self.mining_status_label.setText(f'Minerando... Bloco: {block_index} (Hash anterior: {previous_hash})')
        # Gera o QR Code com os detalhes do bloco
        qr_data = f"Bloco: {block_index}\nHash Anterior: {previous_hash}"
        self.display_qr_code(qr_data)  # Passa os dados do bloco para o QR Code

    def generate_qr_code(self, index, previous_hash):
        qr_data = f"Bloco: {index}\nHash Anterior: {previous_hash}"
        qr_image = qrcode.make(qr_data)
        qr_bytes = BytesIO()
        qr_image.save(qr_bytes, format='PNG')
        qr_pixmap = QPixmap()
        qr_pixmap.loadFromData(qr_bytes.getvalue())
        self.qr_code_label.setPixmap(qr_pixmap.scaled(200, 200, QtCore.Qt.KeepAspectRatio))

        # Botão para ampliar o QR Code
        self.maximize_qr_btn = QPushButton('Ampliar QR Code', self)
        self.maximize_qr_btn.clicked.connect(self.maximize_qr_code)
        layout.addWidget(self.maximize_qr_btn)

    def maximize_qr_code(self):
        qr_data = self.mining_status_label.text()  # Obtém o QR Code baseado na mineração atual
        self.qr_code_window = QrCodeViewer(qr_data)  # Passa o dado do QR Code
        self.qr_code_window.show()

def main():
    app = QtWidgets.QApplication(sys.argv)
    client = CryptoClient()
    client.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    client = CryptoClient()
    client.show()
    sys.exit(app.exec_())