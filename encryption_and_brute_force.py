import time
import math
import os
import pickle
import csv
import matplotlib.pyplot as plt
from typing import Tuple, List


def gcd(a, b):
    """Calculate Greatest Common Divisor using Euclidean algorithm"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Extended Euclidean algorithm for modular inverse"""
    # d*e ≡ 1 mod phi
    old_r, r = e, phi
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    if old_r != 1:
        return None  # Inverse doesn't exist
    return old_s % phi
        
def generate_single_key_pair(min_prime, max_prime):
    """Generate a single RSA key pair (p, q, n) with p != q."""
    while True:
        p = generate_prime_in_range(min_prime, max_prime)
        q = generate_prime_in_range(min_prime, max_prime)
        if p != q:
            n = p * q
            return ((p, q), n)

def generate_increasing_key_pairs(k: int = 10) -> List[Tuple[Tuple[int, int], int]]:
    """
    Generate K key pairs with increasing bit lengths.
    No threading is used since prime generation is now fast.
    """
    key_pairs = []
    base_size = 22  # Start with 22 bits for p and q
    max_bits = 100  # Maximum bit size for n
    
    # Calculate step size to reach max_bits with k key pairs
    step_size = max(1, (max_bits - base_size * 2) // k)

    # Prepare the ranges for each key pair
    for i in range(k):
        current_bits = base_size + (i * step_size // 2)  # Divide by 2 since n = p * q roughly doubles bits
        min_p = 2 ** current_bits + 1
        max_p = 2 ** (current_bits + 1) - 1
        key_pairs.append(generate_single_key_pair(min_p, max_p))

    # Sort key pairs by n size (optional, for increasing order)
    key_pairs.sort(key=lambda pair: pair[1])
    return key_pairs

def brute_force_factorization_optimized(n: int, ciphertext: int, e: int) -> Tuple[str, float]:
    """
    Optimized brute force with several improvements:
    - Skip even numbers (except 2)
    - Check 2 separately
    - Use more efficient modular arithmetic
    - Includes a progress bar
    """
    start_time = time.time()
    
    # Check if n is even (divisible by 2)
    if n % 2 == 0:
        p, q = 2, n // 2
        result = decrypt_message(p, q, n, ciphertext, e, start_time)
        if result[0] is not None:
            return result

    # Check odd numbers only
    sqrt_n = int(math.sqrt(n)) + 1
    progress_step = max(sqrt_n // 100, 1)  # Update every 1%
    for idx, p in enumerate(range(3, sqrt_n, 2)):  # Start at 3, step by 2 (odd numbers only)
        if idx % progress_step == 0 or p == sqrt_n - 1:
            percent = int(100 * idx / (sqrt_n // 2))
            print(f"\r  Brute force progress: {percent}% ({idx}/{sqrt_n // 2})", end='', flush=True)
        if n % p == 0:
            q = n // p
            result = decrypt_message(p, q, n, ciphertext, e, start_time)
            if result[0] is not None:
                print("\r  Brute force progress: 100% (done)           ")
                return result

    end_time = time.time()
    print("\r  Brute force progress: 100% (done)           ")
    return "Failed to decrypt", end_time - start_time

def string_to_number(message: str) -> int:
    """Convert string to number for RSA encryption."""
    result = 0
    for char in message:
        result = result * 256 + ord(char)
    return result

def save_key_pairs(key_pairs, filename="keypairs.pkl"):
    """Save generated key pairs to a file."""
    with open(filename, "wb") as f:
        pickle.dump(key_pairs, f)

def load_key_pairs(filename="keypairs.pkl"):
    """Load key pairs from a file."""
    with open(filename, "rb") as f:
        return pickle.load(f)

def run_rsa_timing_experiment(k: int = 8, use_saved_keys=False):
    """
    Run the complete RSA timing experiment:
    - Generates or loads key pairs
    - Encrypts a message with all keys
    - Brute-forces each private key and decrypts
    - Prints timing summary
    """
    print(f"use_saved_keys = {use_saved_keys}")
    message = "Hi"  # Small message for demonstration
    message_num = string_to_number(message)
    e = 65537  # Common public exponent

    print(f"Original message: {message}")
    print(f"Message as number: {message_num}")
    print(f"Public exponent (e): {e}")
    print("-" * 80)

    keypairs_file = "keypairs.pkl"
    key_pairs = None

    if use_saved_keys and os.path.exists(keypairs_file):
        print("Loading key pairs from file...")
        key_pairs = load_key_pairs(keypairs_file)
        if len(key_pairs) < k:
            print("Not enough key pairs in file, generating more...")
            key_pairs = None

    if key_pairs is None:
        print("Generating key pairs (this may take a while)...")
        keygen_start = time.time()
        key_pairs = generate_increasing_key_pairs(k)
        keygen_end = time.time()
        print(f"Key generation took {keygen_end - keygen_start:.2f} seconds.")
        save_key_pairs(key_pairs, keypairs_file)
    else:
        print(f"Loaded {len(key_pairs)} key pairs from file.")

    # First phase: Encrypt the message with all valid keys
    print("\n" + "=" * 80)
    print("ENCRYPTION PHASE")
    print("=" * 80)
    
    valid_experiments = []
    encryption_times = []
    
    for i, ((p, q), n) in enumerate(key_pairs[:k]):
        print(f"\nEncryption {i+1}/{k}")
        print(f"n = {n} (bit length: {n.bit_length()})")
        print(f"Encrypting message: '{message}' (as number: {message_num})")
        
        # Check if message is smaller than n
        if message_num >= n:
            print(f"Skipping: message ({message_num}) >= n ({n})")
            continue

        phi_n = (p - 1) * (q - 1)
        
        # Check if gcd(e, phi_n) = 1 (required for valid RSA)
        if gcd(e, phi_n) != 1:
            print(f"Skipping: gcd(e, phi_n) != 1")
            continue

        # Time the encryption process
        start_time = time.time()
        ciphertext = pow(message_num, e, n)
        encryption_time = time.time() - start_time
        
        print(f"Encryption time: {encryption_time:.6f} seconds")
        print(f"Ciphertext: {ciphertext}")
        
        # Store valid experiment data
        valid_experiments.append({
            'p': p, 'q': q, 'n': n, 'ciphertext': ciphertext,
            'encryption_time': encryption_time, 'key_size': n.bit_length()
        })
        encryption_times.append(encryption_time)

    # Second phase: Brute force attacks
    print("\n" + "=" * 80)
    print("BRUTE FORCE PHASE")
    print("=" * 80)
    
    brute_force_times = []
    key_sizes = []
    
    for i, exp in enumerate(valid_experiments):
        print(f"\nBrute Force Attack {i+1}/{len(valid_experiments)}")
        print(f"n = {exp['n']} (bit length: {exp['key_size']})")
        
        print("Starting brute force attack...")
        decrypted_message, brute_force_time = brute_force_factorization_optimized(exp['n'], exp['ciphertext'], e)
        
        print(f"Brute force time: {brute_force_time:.6f} seconds")
        print(f"Decrypted message: {decrypted_message}")
        print(f"Success: {'Yes' if decrypted_message == message else 'No'}")
        
        brute_force_times.append(brute_force_time)
        key_sizes.append(exp['key_size'])

    # Print summary
    print("\n" + "=" * 80)
    print("TIMING ANALYSIS SUMMARY")
    print("=" * 80)
    print(f"{'Key Size (bits)':<15} {'Encryption (s)':<15} {'Brute Force (s)':<15}")
    print("-" * 65)

    for i in range(len(key_sizes)):
        print(f"{key_sizes[i]:<15} {encryption_times[i]:<15.6f} {brute_force_times[i]:<15.6f}")

    # Export to CSV
    csv_filename = "rsa_timing_results.csv"
    with open(csv_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Key Size (bits)', 'Encryption Time (s)', 'Brute Force Time (s)'])
        for i in range(len(key_sizes)):
            writer.writerow([key_sizes[i], encryption_times[i], brute_force_times[i]])
    print(f"\nResults exported to {csv_filename}")

    # Generate graphs
    if key_sizes:  # Only create graphs if we have data
        # Graph 1: Key Size vs Encryption Time
        plt.figure(figsize=(10, 6))
        plt.subplot(1, 2, 1)
        plt.plot(key_sizes, encryption_times, 'bo-', linewidth=2, markersize=8)
        plt.xlabel('Key Size (bits)')
        plt.ylabel('Encryption Time (seconds)')
        plt.title('Key Size vs Encryption Time')
        plt.grid(True, alpha=0.3)

        # Graph 2: Key Size vs Brute Force Time
        plt.subplot(1, 2, 2)
        plt.plot(key_sizes, brute_force_times, 'ro-', linewidth=2, markersize=8)
        plt.xlabel('Key Size (bits)')
        plt.ylabel('Brute Force Time (seconds)')
        plt.title('Key Size vs Brute Force Time')
        plt.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig('rsa_timing_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("Graphs saved as rsa_timing_analysis.png")

def generate_prime_in_range(min_val: int, max_val: int) -> int:
    """
    Generate a prime number in the given range using Miller-Rabin and random sampling.
    Much faster than checking every number.
    """
    import random

    def is_probable_prime(n, k=8):
        """Miller-Rabin primality test."""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    # Try up to 10,000 random odd numbers in the range
    for _ in range(10000):
        candidate = random.randrange(min_val | 1, max_val + 1, 2)  # ensure odd
        if is_probable_prime(candidate):
            return candidate
    # Fallback: try every odd number in range
    for candidate in range(min_val | 1, max_val + 1, 2):
        if is_probable_prime(candidate):
            return candidate
    raise ValueError("No primes in the given range")

def decrypt_message(p, q, n, ciphertext, e, start_time):
    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)
    if d is not None:
        decrypted = pow(ciphertext, d, n)
        try:
            message = ""
            temp = decrypted
            while temp > 0:
                message = chr(temp % 256) + message
                temp //= 256
            end_time = time.time()
            return message, end_time - start_time
        except ValueError:
            pass
    return None, None

if __name__ == "__main__":
    run_rsa_timing_experiment(k=20)  # Increase k for more data points