import os
import json
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes as crypt_hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import socket
import time
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

def obter_informacoes_chave_publica(caminho_chave_publica):
    with open(caminho_chave_publica, "rb") as f:
        chave_publica = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    # Verificar tipo de chave e extrair informações
    if isinstance(chave_publica, rsa.RSAPublicKey):
        tipo = "RSA"
        tamanho = chave_publica.key_size
        descricao = f"Chave pública RSA com tamanho de {tamanho} bits, amplamente utilizada para criptografia assimétrica."
    elif isinstance(chave_publica, ec.EllipticCurvePublicKey):
        tipo = "EC"
        curva = chave_publica.curve.name
        descricao = f"Chave pública de curva elíptica (EC), usando a curva {curva}, frequentemente utilizada para criptografia de alta eficiência."
    else:
        tipo = "Desconhecido"
        descricao = "Tipo de chave pública não identificado ou não suportado neste contexto."
    
    return f"Tipo: {tipo}, descricao: {descricao}"

# Função para gerar uma máscara pseudoaleatória com base no nome do atributo e uma senha
def gerar_mascara(senha, nome_atributo):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Usando o SHA-256 do módulo cryptography
        length=32,
        salt=nome_atributo.encode(),
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(senha.encode())  # Gera a máscara

# Função para carregar a chave pública de um arquivo PEM
def carregar_chave_publica(caminho_chave_publica):
    with open(caminho_chave_publica, "rb") as f:
        chave_publica = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return chave_publica

# Função para carregar a chave privada do proprietário (para assinar o pedido)
def carregar_chave_privada(caminho_chave_privada):
    with open(caminho_chave_privada, "rb") as f:
        chave_privada = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return chave_privada

# Função para calcular o compromisso
def calcular_compromisso(nome_atributo, valor_atributo, mascara):
    compromisso = hashlib.sha256()
    compromisso.update(nome_atributo.encode())  # Adiciona o nome do atributo
    compromisso.update(valor_atributo.encode())  # Adiciona o valor do atributo
    compromisso.update(mascara)  # Adiciona a máscara
    return compromisso.hexdigest()


# Função principal para gerar o pedido de DCC (com chave pública)
def gerar_pedido_dcc():
    # Entrada do proprietário
    atributos_valores = {
        "nome": "Diogo Cezar",
        "morada": "Rua Romana",
        "data_nascimento": "01/01/2000",
        "email": "teste@gmail.com"}
    senha = input("Digite sua senha para proteger os atributos: ")

    # Dicionário para armazenar as máscaras
    mascaras = {}
    compromissos = []

    # Gerar a máscara para cada atributo e calcular o compromissos
    for nome_atributo, valor_atributo in atributos_valores.items():
        mascara = gerar_mascara(senha, nome_atributo)
        print(f"Máscara para '{nome_atributo}': {mascara.hex()}")
        mascaras[nome_atributo] = mascara.hex()
        compromisso = calcular_compromisso(nome_atributo, valor_atributo, mascara)
        compromissos.append({
            "label": nome_atributo,
            "value": valor_atributo,
            "commitment": compromisso
        })

    # Carregar a chave pública do proprietário (não será usada para assinar)
    caminho_chave_publica = "public_key_owner.pem"
    chave_publica = carregar_chave_publica(caminho_chave_publica)
    chave_publica_pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Carregar a chave privada do proprietário para assinar
    caminho_chave_privada = "private_key_owner.pem"  # Ajuste o caminho conforme necessário
    chave_privada = carregar_chave_privada(caminho_chave_privada)

    timestamp = os.path.getmtime(caminho_chave_publica)
    timestamp = "{:.6f}".format(timestamp)

    # Criar o pedido de DCC (JSON)
    pedido_dcc = {
        "attributes": compromissos,
        "digest_function": {
            "type": "SHA-256"
        },
        "chave_publica_owner": [
            {
                "value": chave_publica_pem,
                "description of key nature": obter_informacoes_chave_publica(caminho_chave_publica)
            }
        ],
    }

    # Salvar o pedido assinado em um arquivo JSON
    with open('pedido_dcc.json', 'w') as f:
        json.dump(pedido_dcc, f, indent=4)

    print("Pedido de DCC gerado, assinado e salvo como 'pedido_dcc.json'.")

def validar_assinatura(resposta):
    try:
        # Extrair dados da assinatura
        assinatura_data = resposta['Issuer_signature_over_comminments_and_public_key'][0]
        
        assinatura = bytes.fromhex(assinatura_data['value'])
        certificado_pem = assinatura_data['issuer_certificate']
        
        # Carregar o certificado
        certificado = load_pem_x509_certificate(certificado_pem.encode('utf-8'), default_backend())
        chave_publica = certificado.public_key()
        # Concatenar os valores dos commitments e a chave pública do owner
        compromissos_e_chave_publica = []
        for atributo in resposta["attributes"]:
            compromissos_e_chave_publica.append(atributo["commitment"])
        
        compromissos_e_chave_publica.append(resposta["chave_publica_owner"][0]["value"])

        # Gerar os dados para assinar
        dados_para_assinar = json.dumps(compromissos_e_chave_publica, sort_keys=True)
        print("Dados para assinar:", dados_para_assinar)
        hash_dados = hashlib.sha256(dados_para_assinar.encode()).digest()
        chave_publica.verify(
            assinatura,
            hash_dados,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        #verify signature

        print("Assinatura válida: os dados estão íntegros.")
        return True
    except KeyError as e:
        print(f"Erro: chave ausente na resposta: {e}")
        return False
    except ValueError as e:
        print(f"Erro ao processar a assinatura ou certificado: {e}")
        return False
    except Exception as e:
        print(f"Erro inesperado ao validar a assinatura: {e}")
        return False

# Simple socket client to send the request
def enviar_pedido_socket():
    host = 'localhost'  # Endereço do servidor
    port = 5003        # Porta do servidor

    try:
        with open('pedido_dcc.json', 'r') as f:
            pedido_dcc = json.load(f)  # Carrega o conteúdo como dicionário
    except FileNotFoundError:
        print("Erro: Arquivo 'pedido_dcc.json' não encontrado.")
        return
    except json.JSONDecodeError:
        print("Erro: O arquivo 'pedido_dcc.json' contém um JSON inválido.")
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            print(f"Conectando ao servidor {host}:{port}...")
            client_socket.connect((host, port))  # Conecta ao servidor

            # Converte o JSON para string e envia
            client_socket.sendall(json.dumps(pedido_dcc).encode('utf-8'))
            print("Pedido enviado ao servidor.")


            buffer = b""
            print("Recebendo resposta...")
            while True:
                chunk = client_socket.recv(1024)
                if not chunk or chunk == b"":
                    break
                buffer += chunk
            response = buffer.decode('utf-8')
            print("Resposta recebida: ", response)
    except ConnectionRefusedError:
        print("Erro: Não foi possível conectar ao servidor. Verifique se ele está em execução.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")
    
    resposta = json.loads(response)
    dcc = resposta['dcc']
    if validar_assinatura(dcc):
        # Salvar o DCC final em um arquivo JSON
        with open('dcc_final.json', 'w') as f:
            json.dump(dcc, f, indent=4)

        

# Menu for user input
def menu():
    while True:
        print("\nMenu:")
        print("1. Gerar Pedido DCC")
        print("2. Enviar Pedido DCC Para o Issuer")
        print("3. Sair")
        
        escolha = input("Escolha uma opção (1/2/3): ")

        if escolha == '1':
            gerar_pedido_dcc()
        elif escolha == '2':
            enviar_pedido_socket()
        elif escolha == '3':
            print("Saindo...")
            break
        else:
            print("Opção inválida! Tente novamente.")

if __name__ == "__main__":
    menu()