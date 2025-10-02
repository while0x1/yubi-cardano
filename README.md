yubikeys with firmware => 5.7 support signing raw binaries with ED25519 keys stored in the PIV slot.

Using yubico's own yubico-piv-tool you can sign cardano transaction body hashs giving cardano users access to a cheap, ubiquitous hardware wallet option.

Add the yubico-piv-tool repository to the linux advanced package tool to retrieve the latest yubico-piv-tool, or make it from source to ensure you have yubico-piv-tool >= version 2.7.

```bash
sudo add-apt-repository ppa:yubico/stable   
```

run the gen_bundle.py file to create your keys.

It is recommended to do this on an air gapped machine. 

load your priv.pem from the generated keys into the yubikey using the yubico-piv-tool CLI commands.

Run the following command from the directory containing the priv.pem file.<br>
```bash
yubico-piv-tool -s 9c -a import-key -A ED25519 -i priv.pem --touch-policy always --pin-policy always
```

This repo is based on the work done by akonior here - https://github.com/akonior/yubikey-cardano-wallet/blob/main/yubikey_load_keys.sh

