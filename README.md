# Vigenere Cipher Tool

This is a command-line tool that implements the Vigenère cipher for encryption and decryption. The tool supports different gamma modes: Repeat Key, Autokey Plaintext, and Autokey Ciphertext.

## Installation

To build the project, you need:

- **CMake** (v3.10 or later)
- **Boost Program Options** (v1.65 or later)

You can install the dependencies on Ubuntu using:

```sh
sudo apt update
sudo apt install -y cmake libboost-program-options-dev
```

Then, build the project with:

```sh
mkdir build
cd build
cmake ..
make
```

## Usage

The tool provides a command-line interface to encrypt and decrypt text. You can specify the key, gamma mode, action (encrypt or decrypt), and input text.

### Command Line Arguments

- `--key, -k`: Secret key (required).
- `--gamma, -g`: Gamma mode (`repeat`, `auto_plain`, `auto_cipher`). Default is `repeat`.
- `--action, -a`: Action (`encrypt` or `decrypt`). Default is `encrypt`.
- `--text, -t`: Input text. If omitted, the tool reads from stdin.

### Example

To encrypt "HELLO" with a key of "KEY" in repeat mode:

```sh
./vigenere --key KEY --action encrypt --text HELLO
```

Output:

```
RIJVS
```


## Testing

The project includes a set of unit tests to ensure the functionality is correct. You can run the tests with:

```sh
make test
