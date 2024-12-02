
# Secure Notepad

Secure Notepad is a lightweight GTK-based application for securely encrypting, decrypting, and saving textual data. The application uses AES-256-CBC encryption and integrates a Merkle root system for verifying the integrity of the stored data.

## Features

- **Text Encryption**: Secure your text files with AES-256 encryption.
- **Merkle Root Verification**: Calculate and store Merkle roots to ensure data integrity.
- **Graphical Interface**: Simple GTK-based GUI for saving and opening encrypted files.
- **User-Friendly**: Easy-to-use interface for encryption, decryption, and file management.

---

## How It Works

1. **Save Text**: 
   - The application calculates a Merkle root (SHA-256 hash) from the text.
   - The Merkle root is appended to a local file (`pass.txt`).
   - The text is encrypted using AES-256-CBC and saved to the specified file.

2. **Open File**:
   - Users provide the Merkle root key when opening an encrypted file.
   - The application decrypts the file and displays the content in the text editor.

---

## Installation

### Prerequisites

- **C Compiler**: GCC or Clang
- **GTK Development Libraries**: `libgtk-3-dev` or equivalent
- **OpenSSL Development Libraries**: `libssl-dev`

### Build Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/amiriiw/merkle_note.git
   cd merkle_note
   cd Merkle-note
   ```

2. Compile the code:
   ```bash
   gcc -o merkle_note main.c `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto
   ```

3. Run the application:
   ```bash
   ./merkle_note
   ```

---

## Usage

1. **Start the application**:
   - Run the compiled binary to open the Secure Notepad interface.

2. **Saving Text**:
   - Write text in the editor.
   - Click the "Save" button and specify the save location.
   - The Merkle root is stored in `pass.txt`, and the text is encrypted.

3. **Opening Files**:
   - Click the "Open" button and select an encrypted file.
   - Provide the Merkle root key for decryption.
   - The decrypted text is displayed in the editor.

---

## Security

- **Encryption**: AES-256-CBC encryption ensures strong protection for your data.
- **Random Initialization Vector (IV)**: A unique IV is generated for each encryption to enhance security.
- **Merkle Root**: SHA-256 hashes are used for verifying text integrity.

---

## File Structure

- `merkle_note.c`: Main source code for the application.
- `pass.txt`: Stores Merkle roots for saved files.

---

## Known Issues

- Ensure the `pass.txt` file is not shared or deleted, as it contains the Merkle roots for decryption.
- The decryption process may fail if the wrong key is provided or if the file has been tampered with.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- GTK+ for the GUI framework
- OpenSSL for providing robust cryptographic functionality

---

## Contributions

Contributions are welcome! Feel free to submit issues, fork the repository, and open pull requests.
