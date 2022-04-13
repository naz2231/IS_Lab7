from Crypto.Cipher import DES
from time import perf_counter_ns


def bitstringToBytes(s):
    a = int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')
    if len(a) < 8:
        a = bytes(bytearray([0 for _ in range(8 - len(a))])) + a
    return a


def pad(text):
    while len(text) % 8 != 0:
        text += b' '
    return text


def hack(keyLen, encryptedText):
    s = '0b' + "0" * keyLen

    for i in range(2 ** keyLen):
        intKey = int(s, 2) + i
        binKey = bin(intKey)[2:]
        byteKey = bitstringToBytes(binKey)

        des2 = DES.new(byteKey, DES.MODE_ECB)
        decryptedOnce = des2.decrypt(encryptedText)
        for i in range(2 ** keyLen):
            intKey = int(s, 2) + i
            binKey = bin(intKey)[2:]
            byteKey = bitstringToBytes(binKey)
            des2 = DES.new(byteKey, DES.MODE_ECB)
            decryptedTwice = des2.decrypt(decryptedOnce)


def main():
    key = '0000000100000000010000100000000000000001000000001010010000010001'
    keyLen = len(key)
    key = bitstringToBytes(key)
    text = b'Time can never mend The careless whispers of a good friend'
    print(f'TEXT: {text}')

    des = DES.new(key, DES.MODE_ECB)
    padText = pad(text)

    startTime = perf_counter_ns()
    encryptedText = des.encrypt(padText)
    encryptedTwice = des.encrypt(encryptedText)
    print(
        f'Double Encryption time: {(perf_counter_ns() - startTime)/1000000} miliseconds')
    print(f'Encrypted_text: {encryptedText}')
    print(f'Double encrypted_text: {encryptedTwice}')

    startTime = perf_counter_ns()
    decryptedOnce = des.decrypt(encryptedTwice)
    decryptedTwice = des.decrypt(decryptedOnce).decode('utf8')
    print(
        f'Double Decryption time: {(perf_counter_ns() - startTime)/1000000} miliseconds')
    print(f'Decrypted_text: {decryptedOnce}')
    print(f'Double Decrypted_text: {decryptedTwice}')

    # measure hacking time
    # start_time = perf_counter()
    # hack(key_length)
    # end_time = perf_counter() - start_time
    # print(f'Hacking time: {end_time} seconds')


main()
