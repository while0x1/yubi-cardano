yubikeys with firmware => 5.7 support signing raw binaries with ED25519 keys stored in the PIV slot.

Using yubico's own yubico-piv-tool you can sign cardano transaction body hashs giving cardano users access to a cheap, ubiquitous hardware wallet option.

Add the yubico-piv-tool repository to the linux advanced package tool to retrieve the latest yubico-piv-tool, or build it from source to ensure you have yubico-piv-tool >= version 2.7.

```bash
sudo add-apt-repository ppa:yubico/stable
sudo apt update
sudo apt install yubico-piv-tool   
```

run the gen_bundle.py file to create your keys.

It is recommended to do this on an air gapped machine. 

load your priv.pem from the generated keys into the yubikey using the yubico-piv-tool CLI commands.

Run the following command from the directory containing the priv.pem file.<br>
```bash
yubico-piv-tool -s 9c -a import-key -A ED25519 -i priv.pem --touch-policy always --pin-policy always
```

This repo is based on the work done by akonior [here](https://github.com/akonior/yubikey-cardano-wallet/tree/main) this work has a catalyst proposal that deserves funding in Catalyst 14 or support for the research undertaken. 

This extension adds support for yubico-piv-tool, mnemonics, and pycardano transaction building. 

Using a BIP39 mnemonic with a passphrase ensures that if the yubikey is broken or lost the key can be easily regenerated. It also gives the additional bonus that a leaked seephrase will not compromise a wallet without the passphrase also being leaked. 

This hardware wallet has been tested on mainnet and testnet for regular transactions and has been integrated into stealthWallet for an accessible UI for wallet management, transactions and direct DEX integration. 

