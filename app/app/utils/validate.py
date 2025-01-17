import re
import math
from collections import Counter

def validate_login(login, name):
    """Sprawdzanie poprawności loginu"""
    if len(login) < 5 or len(login) > 20:
        raise ValueError(f"{name} musi mieć od 5 do 20 znaków.")
    if not re.match(r'^[a-zA-Z0-9_]+$', login):
        raise ValueError(f"{name} może zawierać tylko litery, cyfry i znak podkreślenia.")
    
def validate_password(password):
    """Sprawdzanie poprawności hasła"""
    if len(password) < 8 or len(password) > 32:
        raise ValueError("Hasło musi mieć co najmniej 8 do 32 znaków.")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Hasło musi zawierać co najmniej jedną wielką literę.")
    if not re.search(r'[0-9]', password):
        raise ValueError("Hasło musi zawierać co najmniej jedną cyfrę.")
    if not re.search(r'[\W_]', password): 
        raise ValueError("Hasło musi zawierać co najmniej jeden znak specjalny.")
    if not re.search(r'[a-z]', password):
        raise ValueError("Hasło musi zawierać co najmniej jedną małą literę.")

def validate_email(email):
    """Sprawdzanie poprawności adresu e-mail"""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise ValueError("Niepoprawny format adresu e-mail.") 
    
def calculate_entropy(password):
    unique_characters = len(Counter(password))
    password_length = len(password)
    entropy = password_length * math.log2(unique_characters) if unique_characters > 1 else 0
    return entropy