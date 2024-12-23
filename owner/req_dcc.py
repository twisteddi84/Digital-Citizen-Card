import json
import hashlib
import socket
import time
from datetime import datetime, timezone
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.x509.oid import NameOID
from PyKCS11 import *
from PyKCS11 import PyKCS11, PyKCS11Error
from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import Sequence


# Função para carregar a chave privada do proprietário
def obter_informacoes_chave_publica(chave_publica):
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
        algorithm=hashes.SHA256(), 
        length=32,
        salt=nome_atributo.encode(),
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(senha.encode())  # Gera a máscara


# Função para calcular o compromisso
def calcular_compromisso(nome_atributo, valor_atributo, mascara):
    compromisso = hashlib.sha256()
    compromisso.update(nome_atributo.encode())  # Adiciona o nome do atributo
    compromisso.update(valor_atributo.encode())  # Adiciona o valor do atributo
    compromisso.update(mascara)  # Adiciona a máscara
    return compromisso.hexdigest()

# Função para carregar a chave privada do proprietário
def get_chave_publica():
    try:
        # Caminho da biblioteca PKCS#11
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        if not slots:
            print("Nenhum cartão encontrado.")
            exit()

        # Selecionar o primeiro slot
        slot = slots[0]
        session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)

        # Localizar o certificado público no cartão
        cert_obj = None
        for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
            attributes = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])
            label = attributes[0]
            if "CITIZEN AUTHENTICATION CERTIFICATE" in label:
                cert_obj = obj
                break

        if not cert_obj:
            print("Certificado público não encontrado.")
            return None

        # Obter o valor do certificado
        cert_attributes = session.getAttributeValue(cert_obj, [PyKCS11.CKA_VALUE])
        cert_der = bytes(cert_attributes[0])

        # Carregar o certificado usando a biblioteca cryptography
        cert = load_der_x509_certificate(cert_der)

        # Extrair a chave pública do certificado
        pub_key = cert.public_key()
        print("Chave pública extraída com sucesso!")

        session.closeSession()
        return pub_key

    except PyKCS11Error as e:
        print(f"Erro ao acessar o cartão: {e}")
    except Exception as e:
        print(f"Erro ao obter a chave pública: {e}")

    return None

# Função para carregar data de nascimento a partir da extensão
def get_birth_date_from_extension(extension):
    try:
        decoded_value, _ = decode(extension)
        for seq in decoded_value:
            if isinstance(seq, Sequence):
                oid = str(seq[0])  # Extract the OID
                if oid == "1.3.6.1.5.5.7.9.1":  # Birth Date OID
                    # Extract the associated value
                    birth_date_raw = seq[1][0]  # Get the SetOf value
                    birth_date_str = birth_date_raw.asOctets().decode()  # Convert to string
                    
                    # Convert the string to a datetime object
                    birth_date = datetime.strptime(birth_date_str, "%Y%m%d%H%M%SZ")
                    
                    # Set timezone to UTC (as 'Z' in the string indicates UTC)
                    birth_date = birth_date.replace(tzinfo=timezone.utc)
                    
                    return birth_date
        return None 
    except Exception as e:
        print(f"Error decoding subjectDirectoryAttributes: {e}")
        return None

# Função principal para gerar o pedido de DCC (com chave pública)
def gerar_pedido_dcc():
    lib = '/usr/local/lib/libpteidpkcs11.so'
    pkcs11 = PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()
    if not slots:
        print("Nenhum cartão encontrado.")
        exit()
    
    slot = slots[0]
    slots = pkcs11.getSlotList(tokenPresent=True)

    full_name = "None"
    id_number = "None"
    country = "None"
    organization = "None"
    birth_date = "None"

    
    for slot in slots:
        token_info = pkcs11.getTokenInfo(slot)
        if "CARTAO DE CIDADAO" in token_info.label:
            print("Portuguese Citizen Card detected.")
            session = pkcs11.openSession(slot)
            try:
                # Look for certificate objects
                objects = session.findObjects([
                    (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE)
                ])
                for obj in objects:
                    attributes = session.getAttributeValue(obj, [
                        PyKCS11.LowLevel.CKA_LABEL,
                        PyKCS11.LowLevel.CKA_VALUE
                    ])
                    
                    label = attributes[0].decode() if isinstance(attributes[0], bytes) else attributes[0]
                    cert_value = attributes[1]
                    if "CITIZEN AUTHENTICATION CERTIFICATE" in label:
                        if isinstance(cert_value, tuple):
                            cert_value = bytes(cert_value)  # Convert tuple of ints to bytes
                        if isinstance(cert_value, bytes):
                            # Parse the certificate
                            cert = load_der_x509_certificate(cert_value)
                            subject = cert.subject
                            # Extract details
                            full_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                            id_number = subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value

                            # Additional data (may require custom OIDs for NIF, NSS, Utent, Birth Date)
                            country = (
                                subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
                                if subject.get_attributes_for_oid(NameOID.COUNTRY_NAME) else None
                            )
                            organization = (
                                subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
                                if subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None
                            )
                          
                            for ex in cert.extensions:
                                oid = ex.oid.dotted_string
                                if oid == "2.5.29.9":  # subjectDirectoryAttributes OID
                                    birth_date = str(get_birth_date_from_extension(ex.value.value))
                        else:
                            print("Certificate value is not in a valid byte format.")
            except Exception as e:
                print(f"Error retrieving data: {e}")
            finally:
                session.closeSession()

    # Entrada do proprietário
    atributos_valores = {
        "nome": full_name,
        "cc_number": id_number,
        "pais": country,
        "organizacao": organization,
        "data_nascimento": birth_date
    }
        
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
    chave_publica = get_chave_publica()
    chave_publica_pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Carregar a chave privada do proprietário para assinar
    # caminho_chave_privada = "private_key_owner.pem"  # Ajuste o caminho conforme necessário
    # chave_privada = carregar_chave_privada(caminho_chave_privada)

    timestamp = time.time()
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
                "description of key nature": obter_informacoes_chave_publica(chave_publica),
            }
        ],
    }

    # Salvar o pedido assinado em um arquivo JSON
    with open('pedido_dcc.json', 'w') as f:
        json.dump(pedido_dcc, f, indent=4)

    print("Pedido de DCC gerado, assinado e salvo como 'pedido_dcc.json'.")

# Função para validar a assinatura do issuer
def validar_assinatura_issuer(resposta):
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

        hash_dados = hashes.Hash(hashes.SHA1(), backend=default_backend())
        hash_dados.update(dados_para_assinar.encode())
        digest = hash_dados.finalize()
        # Verificar a assinatura

        chave_publica.verify(
            assinatura,
            digest,
            ec.ECDSA(hashes.SHA1())
        )

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
    port = 5002        # Porta do servidor

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
    if validar_assinatura_issuer(dcc):
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