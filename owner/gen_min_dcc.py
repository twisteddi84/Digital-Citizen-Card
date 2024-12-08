import json
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Função para gerar uma máscara pseudoaleatória com base no nome do atributo e uma senha fornecida pelo usuário
def gerar_mascara(nome_atributo, senha):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Usando o SHA-256 do módulo cryptography
        length=32,  # Comprimento da máscara gerada
        salt=nome_atributo.encode(),  # Salt é o nome do atributo codificado
        iterations=100000,  # Número de iterações
        backend=default_backend()
    )
    
    # Gera a máscara com base na senha e no nome do atributo
    mascara = kdf.derive(senha.encode())  # Gera a máscara

    return mascara

# Função para codificar em base64
def encode_base64(data):
    return base64.b64encode(data).decode('utf-8')  # Codifica e retorna como string

# Função para carregar a chave privada do proprietário (em formato PEM)
def carregar_chave_privada(caminho_arquivo):
    with open(caminho_arquivo, 'rb') as f:
        chave_privada = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    return chave_privada

# Função para gerar a assinatura usando a chave privada do proprietário
def assinar_dcc(chave_privada, dados_para_assinar):
    # Calcular o hash do conteúdo para assinar
    hash_dados = hashlib.sha256(dados_para_assinar.encode('utf-8')).digest()

    # Assinar os dados (hash) com a chave privada
    assinatura = chave_privada.sign(
        hash_dados,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return assinatura

def gerar_dcc_com_atributos_visiveis():
    # Pedir ao utilizador para inserir o nome do arquivo JSON com o DCC final
    nome_arquivo = input("Digite o nome do arquivo JSON do DCC final: ")

    try:
        # Tentar carregar o conteúdo do arquivo JSON
        with open(nome_arquivo, 'r') as f:
            dcc_final = json.load(f)
    except FileNotFoundError:
        print(f"Erro: Arquivo '{nome_arquivo}' não encontrado.")
        return
    except json.JSONDecodeError:
        print(f"Erro: O arquivo '{nome_arquivo}' contém um JSON inválido.")
        return

    # Listar os atributos disponíveis no DCC final
    atributos = [atributo['label'] for atributo in dcc_final['attributes']]
    print("Atributos disponíveis no DCC final:")
    for idx, atributo in enumerate(atributos, start=1):
        print(f"{idx}. {atributo}")

    # Pedir ao utilizador para escolher os atributos que deseja manter visíveis
    atributos_visiveis = []
    while True:
        try:
            escolha = input("Digite o número do atributo que deseja manter visível (ou 'sair' para terminar): ")
            if escolha.lower() == 'sair':
                break
            escolha = int(escolha)
            if 1 <= escolha <= len(atributos):
                atributo_escolhido = atributos[escolha - 1]
                if atributo_escolhido not in atributos_visiveis:
                    atributos_visiveis.append(atributo_escolhido)
                    print(f"Atributo '{atributo_escolhido}' adicionado aos visíveis.")
                else:
                    print(f"O atributo '{atributo_escolhido}' já foi adicionado.")
            else:
                print("Número inválido. Tente novamente.")
        except ValueError:
            print("Entrada inválida. Tente novamente.")

    # Filtrar o DCC final para manter apenas os atributos visíveis e adicionar os compromissos
    print(dcc_final)
    senha = input("Digite a senha para gerar as máscaras: ")
    dcc_filtrado = {
        "commitments": [
            attr['commitment']  # Inclui todos os valores de commitment, independentemente de serem visíveis ou não
            for attr in dcc_final['attributes']  # Agora sem filtro de atributos visíveis
        ],
        "digest_function": dcc_final["digest_function"],
        "attributes": [
            {
                "label": atributo["label"],
                "value": atributo["value"],  # valor original do atributo
                "mask": encode_base64(gerar_mascara(atributo["label"], senha))  # Gera e adiciona a máscara
            }
            for atributo in dcc_final["attributes"]
            if atributo["label"] in atributos_visiveis
        ],
        "chave_publica_owner": dcc_final["chave_publica_owner"],
        "Issuer_signature": dcc_final["Issuer_signature_over_comminments_and_public_key"]
    }

    # Carregar a chave privada do proprietário (substitua pelo caminho correto)
    chave_privada_owner = carregar_chave_privada("private_key_owner.pem")

    # Gerar a assinatura do DCC
    dcc_filtrado_str = json.dumps(dcc_filtrado, sort_keys=True)  # Converter o DCC filtrado para string para assinar
    print("Dados a assinar: ", dcc_filtrado_str)
    assinatura = assinar_dcc(chave_privada_owner, dcc_filtrado_str)

    # Adicionar a assinatura ao DCC
    timestamp = time.time()
    dcc_filtrado["Owner_signature"] = {
        "signature_value": assinatura.hex(),
        "timestamp": timestamp,
        "crypto_system": "RSA PKCS1v15 with SHA256"
    }

    # Salvar o novo DCC com os atributos visíveis escolhidos e a assinatura
    novo_nome_arquivo = "min_dcc.json"
    with open(novo_nome_arquivo, 'w') as f:
        json.dump(dcc_filtrado, f, indent=4)

    print(f"Min DCC gerado e assinado salvo como '{novo_nome_arquivo}'.")

# Atualizar o menu para incluir a opção de gerar o novo DCC
def menu():
    while True:
        print("\nMenu:")
        print("1. Gerar DCC com Atributos Visíveis")
        print("2. Sair")
        
        escolha = input("Escolha uma opção (1/2): ")
        if escolha == '1':
            gerar_dcc_com_atributos_visiveis()
        elif escolha == '2':
            print("Saindo...")
            break
        else:
            print("Opção inválida! Tente novamente.")

if __name__ == "__main__":
    menu()
