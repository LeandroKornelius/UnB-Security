from parte_1 import generate_keypair, save_key, load_key
from parte_2 import sign_message, save_signature, load_signature
from parte_3 import verify_signature
import os

def write_sample_message(filename="mensagem.txt"):
    message = b"Esta mensagem e secreta e sera assinada digitalmente."
    with open(filename, "wb") as f:
        f.write(message)
    print("Mensagem de teste salva no arquivo 'mensagem.txt'.")
    return message

def run_tests():
    print("\n=== TESTE 1: Gerando par de chaves RSA ===")
    public_key, private_key = generate_keypair()
    save_key(public_key, "public_key.pem")
    save_key(private_key, "private_key.pem")
    print("Chaves geradas com sucesso e salvas nos arquivos 'public_key.pem' e 'private_key.pem'.")
    print(f"Chave pública (e, n): {public_key}")
    print(f"Chave privada (d, n): {private_key}")

    print("\n=== TESTE 2: Salvando mensagem de teste ===")
    message = write_sample_message()

    print("\n=== TESTE 3: Assinando a mensagem ===")
    signature = sign_message(message, private_key)
    save_signature(signature, "assinatura.sig")
    print("✍A mensagem foi assinada e a assinatura foi salva em 'assinatura.sig'.")
    print("Assinatura (em Base64):", open("assinatura.sig", "rb").read().decode())

    print("\n=== TESTE 4: Carregando chave pública e assinatura para verificação ===")
    public_key_loaded = load_key("public_key.pem")
    signature_loaded = load_signature("assinatura.sig")
    print("Chave pública e assinatura carregadas com sucesso.")

    print("\n=== TESTE 5: Verificando a assinatura ===")
    is_valid = verify_signature(message, signature_loaded, public_key_loaded)
    if is_valid:
        print("Resultado esperado: A assinatura é válida para esta mensagem.")
    else:
        print("ERRO: A assinatura deveria ser válida, mas não foi verificada corretamente.")

    print("\n=== TESTE 6: Teste negativo - Alterando a mensagem ===")
    altered_message = b"Esta mensagem foi alterada maliciosamente!"
    is_still_valid = verify_signature(altered_message, signature_loaded, public_key_loaded)
    if not is_still_valid:
        print("Resultado esperado: A assinatura **não é mais válida** após alterar a mensagem.")
    else:
        print("ERRO: A assinatura foi considerada válida mesmo com a mensagem alterada.")

    print("\n=== TODOS OS TESTES FORAM EXECUTADOS ===")

if __name__ == "__main__":
    run_tests()
