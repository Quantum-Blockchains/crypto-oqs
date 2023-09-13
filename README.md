# crypto-oqs
Utility for generating, sign and verification message with Dilithium keys.
## Build
1. install rust
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    ```bash
    $HOME/.cargo/env
    ```
2. install make
    ```bash
    sudo apt update
    ```
    ```bash
    sudo apt install make
    ```
3. build project
    ```bash
    make
    ```
## Comands
1. generate - generate key pair 
    ```bash
   crypto-oqs generate --algorithm dilithium5 --out key.pem
    ```
2. public - pull the public key from the pair
    ```bash
    crypto-oqs public --in key.pem --out pub.pem
    ```
3. sign - sign the file
    ```bash
    crypto-oqs sign --sec key.pem --out signature --file <PATH>
    ```
4. verify - verification the file
   ```bash
    crypto-oqs verify --sig signature --pub pub.pem --file <PATH>
    ```

