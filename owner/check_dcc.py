import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509 import load_pem_x509_certificate
from PyKCS11 import *


# Função para calcular o compromisso
def calcular_compromisso(nome_atributo, valor_atributo, mascara):
    compromisso = hashlib.sha256()
    compromisso.update(nome_atributo.encode())  # Adiciona o nome do atributo
    compromisso.update(valor_atributo.encode())  # Adiciona o valor do atributo
    compromisso.update(mascara)  # Adiciona a máscara
    return compromisso.hexdigest()

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



def validar_assinatura_issuer(resposta):
    try:
        # Extrair dados da assinatura
        assinatura_data = resposta['Issuer_signature'][0]
        assinatura = bytes.fromhex(assinatura_data['value'])
        certificado_pem = assinatura_data['issuer_certificate']
        
        # Carregar o certificado
        certificado = load_pem_x509_certificate(certificado_pem.encode('utf-8'), default_backend())
        chave_publica = certificado.public_key()
        # Concatenar os valores dos commitments e a chave pública do owner
        compromissos_e_chave_publica = []
        for atributo in resposta["commitments"]:
            compromissos_e_chave_publica.append(atributo)
        
        compromissos_e_chave_publica.append(resposta["chave_publica_owner"][0]["value"])

        # Gerar os dados para assinar
        dados_para_assinar = json.dumps(compromissos_e_chave_publica, sort_keys=True)

        hash_dados = hashes.Hash(hashes.SHA1(), backend=default_backend())
        hash_dados.update(dados_para_assinar.encode())
        digest = hash_dados.finalize()

        # Verificar a assinatura
        chave_publica.verify(
            assinatura,
            digest,
            ec.ECDSA(hashes.SHA1())
        )

        print("Assinatura do Issuer válida: os dados estão íntegros.")
        return True
    except KeyError as e:
        print(f"Erro: chave ausente na resposta: {e}")
        return False
    except ValueError as e:
        print(f"Erro ao processar a assinatura ou certificado: {e}")
        return False
    except Exception as e:
        print(f"Assinatura do Issuer inválida ou documento adulterado: {e}")

        
        return False



def validar_assinatura_owner(chave_publica, dados_para_validar, assinatura):
    try:
        # Carregar a chave pública a partir da string PEM
        chave_publica = serialization.load_pem_public_key(
            chave_publica.encode('utf-8'),
            backend=default_backend()
        )

        # Converter a assinatura de hexadecimal para bytes
        assinatura_bytes = bytes.fromhex(assinatura)

        dados_bytes = dados_para_validar.encode('utf-8')

        # Verificar a assinatura utilizando a chave pública
        chave_publica.verify(
            assinatura_bytes,  # A assinatura a ser validada
            dados_bytes,  # O hash dos dados originais
            padding.PKCS1v15(),  # O esquema de padding
            hashes.SHA512()  # O algoritmo de hash utilizado
        )

        print("Assinatura do Owner válida: os dados estão íntegros.")
    
    except ValueError as e:
        print(f"Erro ao verificar a assinatura: {e}")
    except Exception as e:
        print(f"Assinatura do Owner inválida ou documento adulterado: {e}")

    
def verificarCompromisso(nome_atributo, valor_atributo, mascara, lista_compromissos):
    # Calcular o compromisso
    compromisso_calculado = calcular_compromisso(nome_atributo, valor_atributo, mascara)
    
    # Verificar se o compromisso calculado é igual ao compromisso fornecido
    if compromisso_calculado in lista_compromissos:
        print(f"O compromisso do atributo '{nome_atributo}' é válido.")
    else:
        print(f"O compromisso do atributo '{nome_atributo}' é inválido.")
    

# Função para ver os dados do DCC
def verDados(dcc_doc):
    try:
        # Carregar o arquivo DCC (em formato JSON)
        with open(dcc_doc, 'r') as file:
            dcc_data = json.load(file)
        
        # Verifica se o campo 'attributes' existe no DCC
        if 'attributes' in dcc_data:
            # Itera sobre os atributos e imprime os valores dos visíveis
            for atributo in dcc_data['attributes']:
                # Verifica se o atributo é visível (aqui supomos que um atributo tenha o campo 'visivel')
                print(f"{atributo['label']}: {atributo['value']}")
        else:
            print("O DCC não contém a chave 'attributes'.")
    
    except FileNotFoundError:
        print(f"Arquivo {dcc_doc} não encontrado.")
    except json.JSONDecodeError:
        print(f"Erro ao decodificar o arquivo JSON.")
    except Exception as e:
        print(f"Ocorreu um erro: {str(e)}")

def decode_base64(data):
    return base64.b64decode(data) 




# Atualizar o menu para incluir a opção de gerar o novo DCC
def menu():
    dcc_doc = input("Digite o nome do arquivo JSON do DCC a analisar: ")
    while True:
        print("\nMenu:")
        print("1. Ver Dados do DCC")
        print("2. Validar Integridade dos Dados")
        print("3. Sair")
        
        escolha = input("Escolha uma opção (1/2/3): ")
        if escolha == '1':
            verDados(dcc_doc)
        elif escolha == '2':
            open_dcc_doc = json.load(open(dcc_doc))
            validar_assinatura_issuer(open_dcc_doc)

            chave_publica = open_dcc_doc["chave_publica_owner"][0]["value"]
            #retirar o campo Owner_signature
            dcc_doc_filtrado = open_dcc_doc.copy()
            dcc_doc_filtrado.pop("Owner_signature")
            dcc_doc_filtrado = json.dumps(dcc_doc_filtrado, sort_keys=True)
            validar_assinatura_owner(chave_publica, dcc_doc_filtrado, open_dcc_doc["Owner_signature"]["signature_value"])

            for atributo in open_dcc_doc["attributes"]:
                print(f"Verificando compromisso do atributo '{atributo['label']}', valor: '{atributo['value']},' máscara: '{atributo['mask']}'")
                verificarCompromisso(atributo["label"], atributo["value"], decode_base64(atributo["mask"]), open_dcc_doc["commitments"])
        elif escolha == '3':
            break
        else:
            print("Opção inválida! Tente novamente.")

if __name__ == "__main__":
    menu()