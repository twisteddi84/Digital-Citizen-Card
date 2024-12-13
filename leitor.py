from PyKCS11 import *
import binascii
from PyKCS11 import PyKCS11, PyKCS11Error
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding

# Caminho da biblioteca PKCS#11
lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11Lib()
pkcs11.load(lib)

# Listar slots disponíveis
slots = pkcs11.getSlotList()
if not slots:
    print("Nenhum cartão encontrado.")
    exit()

# Selecionar o primeiro slot
slot = slots[0]
session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)

# Solicitar o PIN ao usuário
pin = input("Insira o PIN: ")
try:
    session.login(pin)
    print("Autenticação com PIN bem-sucedida.")
except PyKCS11Error as e:
    print(f"Erro ao autenticar: {e}")
    exit()



def assinar_com_chave_privada(session, dados):
    try:
        # Localizar a chave privada no cartão
        priv_key_obj = None
        for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]):
            attributes = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])
            label = attributes[0]
            if "SIGNATURE KEY" in label:
                priv_key_obj = obj
                break

        if not priv_key_obj:
            print("Chave privada não encontrada.")
            return None

        # Mecanismo para assinatura
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)

        # Assinar os dados
        assinatura = session.sign(priv_key_obj, dados, mechanism)
        assinatura_bytes = bytes(assinatura)  # Converter para bytes
        print("Assinatura gerada com sucesso!")
        return assinatura_bytes

    except PyKCS11Error as e:
        print(f"Erro ao acessar o cartão: {e}")
    except Exception as e:
        print(f"Erro na assinatura: {e}")

    return None

def verificar_assinatura(session, assinatura, dados):
    try:
        # Localizar o certificado público no cartão
        pub_key_obj = None
        for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
            attributes = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])
            label = attributes[0]
            if "SIGNATURE CERTIFICATE" in label:
                pub_key_obj = obj
                break

        if not pub_key_obj:
            print("Certificado público não encontrado.")
            return False

        # Obter o valor do certificado
        pub_key_attributes = session.getAttributeValue(pub_key_obj, [PyKCS11.CKA_VALUE])
        cert_der = bytes(pub_key_attributes[0])

        # Carregar o certificado usando a biblioteca cryptography
        cert = load_der_x509_certificate(cert_der)

        # Extrair a chave pública do certificado
        pub_key = cert.public_key()

        # Verificar a assinatura
        pub_key.verify(
            assinatura,  # Assinatura a ser verificada
            dados,       # Dados originais
            padding.PKCS1v15(),
            SHA256()
        )

        print("Assinatura verificada com sucesso!")
        return True

    except PyKCS11Error as e:
        print(f"Erro ao acessar o cartão: {e}")
    except Exception as e:
        print(f"Erro na verificação: {e}")

    return False

# Exemplo de uso (integração):
message = b"Mensagem para assinatura"  # Dados originais a serem assinados e verificados

# Assumindo que a sessão já foi aberta (session)
assinatura = assinar_com_chave_privada(session, message)
if assinatura:
    print(f"Assinatura gerada: {binascii.hexlify(bytearray(assinatura)).decode()}")
    verificar_assinatura(session, assinatura, message)

# Fechar a sessão
session.logout()
session.closeSession()






