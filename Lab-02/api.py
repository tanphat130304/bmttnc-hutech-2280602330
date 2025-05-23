from flask import Flask, request, jsonify
from cipher.vigenere import VigenereCipher
from cipher.caesar import CaesarCipher

app = Flask(__name__)

vigenere_cipher = VigenereCipher()
caesar_cipher = CaesarCipher()

@app.route("/api/vigenere/encrypt", methods=["POST"])
def vigenere_encrypt():
    try:
        data = request.json
        if not data or 'plain_text' not in data or 'key' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        plain_text = data['plain_text']
        key = str(data['key'])  # Vigenere key should be string
        
        if not plain_text or not key:
            return jsonify({'error': 'Empty text or key not allowed'}), 400
            
        encrypted_text = vigenere_cipher.vigenere_encrypt(plain_text, key)
        return jsonify({'encrypted_message': encrypted_text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/vigenere/decrypt", methods=["POST"])
def vigenere_decrypt():
    try:
        data = request.json
        if not data or 'cipher_text' not in data or 'key' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        cipher_text = data['cipher_text']
        key = str(data['key'])  # Vigenere key should be string
        
        if not cipher_text or not key:
            return jsonify({'error': 'Empty text or key not allowed'}), 400
            
        decrypted_text = vigenere_cipher.vigenere_decrypt(cipher_text, key)
        return jsonify({'decrypted_message': decrypted_text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/caesar/encrypt", methods=["POST"])
def caesar_encrypt():
    try:
        data = request.json
        if not data or 'plain_text' not in data or 'key' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        plain_text = data['plain_text']
        key = int(data['key'])  # Caesar key should be integer
        
        if not plain_text:
            return jsonify({'error': 'Empty text not allowed'}), 400
            
        encrypted_text = caesar_cipher.encrypt_text(plain_text, key)
        return jsonify({'encrypted_message': encrypted_text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/caesar/decrypt", methods=["POST"])
def caesar_decrypt():
    try:
        data = request.json
        if not data or 'cipher_text' not in data or 'key' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        cipher_text = data['cipher_text']
        key = int(data['key'])  # Caesar key should be integer
        
        if not cipher_text:
            return jsonify({'error': 'Empty text not allowed'}), 400
            
        decrypted_text = caesar_cipher.decrypt_text(cipher_text, key)
        return jsonify({'decrypted_message': decrypted_text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
