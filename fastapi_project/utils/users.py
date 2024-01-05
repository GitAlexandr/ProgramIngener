import hashlib
import random
import string


def get_random_string(length=12):
    """Генерирует случайную строку, использующуюся как соль"""
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


def hash_password(password: str, salt: str = None):
    """Хеширует пароль с солью"""
    if salt is None:
        salt = get_random_string()
    enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return enc.hex()


def validate_password(password: str, hashed_password: str):
    """Проверяет, что хеш пароля совпадает с хешем из БД"""
    salt, hashed = hashed_password.split("$")
    return hash_password(password, salt) == hashed
