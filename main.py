import tkinter as tk
import base64
import pyffx

def fpe_encrypt(input_string, encryption_key):
    try:
        # Define the alphabet for uppercase letters and digits
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

        # Convert any lowercase letters to uppercase
        input_string = input_string.upper()

        # Determine the radix based on the number of characters in the alphabet
        radix = len(alphabet)

        # Create an FF1 cipher object with the length of the input string
        cipher = pyffx.String(encryption_key, alphabet=alphabet, length=len(input_string))

        # Encrypt the input string
        encrypted_string = cipher.encrypt(input_string)

        return encrypted_string
    except Exception as e:
        print(f"Error: {e}")
        return None

def fpe_decrypt(encrypted_string, encryption_key):
    try:
        # Define the alphabet for uppercase letters and digits
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

        # Remove non-alphabet characters from the encrypted string
        encrypted_string = ''.join(char for char in encrypted_string if char in alphabet)

        # Convert the encryption key to bytes (assuming UTF-8 encoding)
        encryption_key_bytes = encryption_key.encode('utf-8')

        # Determine the radix based on the number of characters in the alphabet
        radix = len(alphabet)

        # Create an FF1 cipher object with the length of the sanitized encrypted string
        cipher = pyffx.String(encryption_key_bytes, alphabet=alphabet, length=len(encrypted_string))

        # Decrypt the sanitized encrypted string
        decrypted_string = cipher.decrypt(encrypted_string)

        return decrypted_string
    except Exception as e:
        print(f"Error: {e}")
        return None

def encode_text():
    input_text = input_entry.get()
    modifier = modifier_entry.get()
    modifier = modifier.upper()
    your_callsign = callsign_entry.get()
    your_callsign = your_callsign.upper()
    distant_callsign = distant_callsign_entry.get()
    distant_callsign = distant_callsign.upper()
    prepared_text = your_callsign + input_text + modifier
    encrypted_text = fpe_encrypt(prepared_text, encryption_key.get().encode('utf-8'))
    combined_text = (your_callsign + ":" + distant_callsign + " " + encrypted_text)
    output_text.set(combined_text)

def decode_text():
    input_text = input_entry.get()
    decrypted_text = fpe_decrypt(input_text, encryption_key.get())
    output_text.set(decrypted_text)

def clear_inputs():
    input_entry.delete(0, tk.END)
    #encryption_key.delete(0, tk.END)
    output_text.set("")

# Create the main window
root = tk.Tk()
root.title("Cryption")
root.geometry("225x325")

# Create and place widgets
input_label = tk.Label(root, text="Enter full 8 digit grid:")
input_label.pack()

input_entry = tk.Entry(root)
input_entry.pack()

modifier_label = tk.Label(root, text="Enter Single Character Modifier:")
modifier_label.pack()

modifier_entry = tk.Entry(root)
modifier_entry.pack()

callsign_label=tk.Label(root, text="Your 3 Character Callsign:")
callsign_label.pack()

callsign_entry = tk.Entry(root)
callsign_entry.pack()

distant_callsign_label = tk.Label(root, text="Distant 3 Character Callsign:")
distant_callsign_label.pack()

distant_callsign_entry= tk.Entry(root)
distant_callsign_entry.pack()

key_label = tk.Label(root, text="Enter encryption key:")
key_label.pack()

encryption_key = tk.Entry(root)
encryption_key.pack()

encode_button = tk.Button(root, text="Encode", command=encode_text, width=150)
encode_button.pack()

decode_button = tk.Button(root, text="Decode", command=decode_text, width=150)
decode_button.pack()

clear_button = tk.Button(root, text="Clear Inputs", command=clear_inputs, width=150)
clear_button.pack()

output_label = tk.Label(root, text="Output:")
output_label.pack()

output_text = tk.StringVar()
output_entry = tk.Entry(root, textvariable=output_text, width=200, justify='center')
output_entry.pack()

# Run the application
root.mainloop()
