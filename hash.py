import hashlib
import bcrypt

# Définir les algorithmes de hachage disponibles
hash_algorithms = {
    "MD5": hashlib.md5,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
    "bcrypt": bcrypt.hashpw,
}

# Demander à l'utilisateur de saisir la chaîne à hasher
password = input("Entrez la chaîne à hasher : ")
# Demander à l'utilisateur de choisir l'algorithme de hachage
print("Algorithmes de hachage disponibles :")
for key in hash_algorithms.keys():
    print(key)
algorithm = input("Choisissez l'algorithme de hachage : ")
# Vérifier que l'algorithme de hachage est disponible
if algorithm not in hash_algorithms:
    print("Erreur : algorithme de hachage invalide")
    exit()

if algorithm == 'bcrypt':
    salt = bcrypt.gensalt()
    hashed = hash_algorithms[algorithm](password.encode('utf-8'), salt)
    print("Chaîne : {}".format(password))
    print("Salt : {}".format(salt.decode('utf-8')))
    print("Hachage : {}".format(hashed.decode('utf-8')))
else:
    # Hacher la chaîne et l'afficher
    hash_object = hash_algorithms[algorithm](password.encode('utf-8'))
    print("Chaîne : {}".format(password))
    print("Hachage : {}".format(hash_object.hexdigest()))
