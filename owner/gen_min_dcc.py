import json
import time
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PyKCS11 import *
from PyKCS11 import PyKCS11, PyKCS11Error

# Função para gerar uma máscara pseudoaleatória com base no nome do atributo e uma senha fornecida
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
    return base64.b64encode(data).decode('utf-8') 

# Função para assinar dados com a chave privada do cartão
def assinar_com_chave_privada(dados):
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

        # Localizar a chave privada no cartão
        priv_key_obj = None

        try:
            priv_key_obj = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY")])[0]
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA512_RSA_PKCS)
            assinatura = session.sign(priv_key_obj, dados, mechanism)
            assinatura_bytes = bytes(assinatura)  # Converter para bytes
            session.closeSession()
            print("Assinatura gerada com sucesso!")
            return assinatura_bytes, "CKM_SHA512_RSA_PKCS"
        except IndexError:
            print("Chave privada não encontrada.")
            return None, None

    except PyKCS11Error as e:
        print(f"Erro ao acessar o cartão: {e}")
    except Exception as e:
        print(f"Erro na assinatura: {e}")

    return None, None


# Função para gerar o DCC com os atributos visíveis escolhidos
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
            # Exibir atributos visíveis
            if atributos_visiveis:
                print("\nAtributos visíveis: ", ", ".join(atributos_visiveis))
            else:
                print("\nNenhum atributo visível ainda.")

            # Solicitar entrada do usuário
            escolha = input("\nDigite o número do atributo que deseja manter visível (ou 'gerar' para gerar min dcc): ")

            # Se o usuário digitar 'gerar', sair do loop
            if escolha.lower() == 'gerar':
                break

            # Converter a entrada para número inteiro
            escolha = int(escolha)

            # Validar se o número está dentro do intervalo dos atributos
            if 1 <= escolha <= len(atributos):
                atributo_escolhido = atributos[escolha - 1]

                # Se o atributo já estiver na lista, removê-lo
                if atributo_escolhido in atributos_visiveis:
                    atributos_visiveis.remove(atributo_escolhido)
                    print(f"Atributo '{atributo_escolhido}' removido dos visíveis.")
                else:
                    # Caso contrário, adicioná-lo
                    atributos_visiveis.append(atributo_escolhido)
                    print(f"Atributo '{atributo_escolhido}' adicionado aos visíveis.")
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

    # Gerar a assinatura do DCC
    dcc_filtrado_str = json.dumps(dcc_filtrado, sort_keys=True)
    print("Dados a assinar: ", dcc_filtrado_str)
    assinatura, mecanismo = assinar_com_chave_privada(dcc_filtrado_str)

    # Adicionar a assinatura ao DCC
    timestamp = time.time()
    dcc_filtrado["Owner_signature"] = {
        #bytes to string
        "signature_value": assinatura.hex(),
        "timestamp": timestamp,
        "crypto_system": str(mecanismo)
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
