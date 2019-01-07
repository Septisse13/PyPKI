import KeyPolicy

keyPolicy = KeyPolicy.KeyPolicy(1000, "rsa2048", b"aes-192-cbc")

keyPolicy.duration = 1000
keyPolicy.algorithm = "rsa2048"

print(keyPolicy.encryption)
