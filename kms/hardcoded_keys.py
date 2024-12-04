import base64
kyber_private_key = b'your-kyber-private-key-bytes'
KYBER_PRIVATE_KEY_B64 = base64.b64encode(kyber_private_key).decode('utf-8')
print('kyber_priv_key: ', kyber_private_key)
print('kyber_priv_key_b64: ' + KYBER_PRIVATE_KEY_B64)

