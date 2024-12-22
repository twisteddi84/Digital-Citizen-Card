import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import time
import socket

# Define the server address and port
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5002      # Port to listen on



def assinar_dados(chave_privada, dados):
    # Calcula o hash dos dados
    hash_dados = hashes.Hash(hashes.SHA1(), backend=default_backend())
    hash_dados.update(dados.encode())
    digest = hash_dados.finalize()
    
    # Assina os dados com a chave privada
    assinatura = chave_privada.sign(
        digest,
        ec.ECDSA(hashes.SHA1())
    )
    return assinatura


# Função para carregar o certificado do issuer
def carregar_certificado_issuer(caminho_certificado):
    with open(caminho_certificado, "r") as f:
        certificado = f.read()
    return certificado


# Função para gerar o DCC final
def completar_dcc(pedido_dcc):

    # Carregar a chave privada do issuer
    with open("chave_privada_ec.pem", "rb") as f:
        chave_privada_issuer = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Extrair os compromissos e a chave pública do owner para gerar a assinatura
    compromissos_e_chave_publica = []
    for atributo in pedido_dcc["attributes"]:
        compromissos_e_chave_publica.append(atributo["commitment"])
    
    compromissos_e_chave_publica.append(pedido_dcc["chave_publica_owner"][0]["value"])

    # Gerar os dados para assinar
    dados_para_assinar = json.dumps(compromissos_e_chave_publica, sort_keys=True)
    assinatura_issuer = assinar_dados(chave_privada_issuer, dados_para_assinar)

    # Carregar o certificado do issuer
    certificado_issuer = carregar_certificado_issuer("certificado_autoassinado.pem")

    # Preparar a estrutura para a assinatura do issuer sobre compromissos e chave pública
    issuer_signature_over_commitments_and_public_key = {
        "value": assinatura_issuer.hex(),
        "timestamp": time.time(),
        "description": "Assinatura com Elliptic Curve (ECDSA) e SHA-1",
        "issuer_certificate": certificado_issuer
    }

    # Preparar o JSON final no formato desejado
    dcc_final = {
        "attributes": pedido_dcc["attributes"],
        "digest_function": pedido_dcc["digest_function"],
        "chave_publica_owner": pedido_dcc["chave_publica_owner"],
        "Issuer_signature_over_comminments_and_public_key": [
            issuer_signature_over_commitments_and_public_key
        ]
    }


    # Salvar o DCC final em um arquivo JSON
    with open('dcc_final.json', 'w') as f:
        json.dump(dcc_final, f, indent=4)

    print("DCC final gerado e salvo como 'dcc_final.json'.")
    return dcc_final

# Simple socket server to handle requests
def socket_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()  # Permitir uma conexão por vez
        print(f"Listening for connections on {HOST}:{PORT}...")

        while True:
            client_socket, client_address = server_socket.accept()
            with client_socket:
                print(f"Connected by {client_address}")
                try:
                    print("Receiving request...")
                    # Lê a requisição do cliente
                    buffer = b""
                    while True:
                        chunk = client_socket.recv(1024)  # Lê em pedaços
                        if not chunk:  # Se não houver mais dados, termina a leitura
                            break
                        buffer += chunk
                        try:

                            request = buffer.decode('utf-8')  # Converte os bytes para string
                            request_dict = json.loads(request)  # Converte a string para JSON (dicionário)

                            # Processa a requisição e gera o DCC
                            dcc_final = completar_dcc(request_dict)  # Passa o dicionário aqui
                            print(f"Generated DCC: {dcc_final}")  # Debug print

                            # Envia a resposta de volta ao cliente
                            response = json.dumps({"status": "success", "dcc": dcc_final})
                            client_socket.sendall(response.encode('utf-8'))  # Envia a resposta
                            print("Response sent.")
                            break  # Encerra o loop
                        except json.JSONDecodeError:
                            print("Erro: A requisição não é um JSON válido.")
                            error_response = json.dumps({"status": "error", "message": "Invalid JSON request"})

                except Exception as e:
                    # Caso haja erro, envia uma resposta de erro
                    error_response = json.dumps({"status": "error", "message": str(e)})
                finally:
                    print("Connection closed.")


if __name__ == "__main__":
    socket_server()