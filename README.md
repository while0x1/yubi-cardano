yubikeys with firmware => 5.7 support signing raw binaries with ED25519 keys stored in the PIV slot.

Using yubico's own yubico-piv-tool you can sign cardano transaction body hashs.

Add the yubico-piv-tool repository to the linux advanced package tool to retrieve the latest yubico-piv-tool, or make it from source to ensure you have yubico-piv-tool >= version 2.7.

sudo add-apt-repository ppa:yubico/stable   

This repo is based on the work done by akonior here - https://github.com/akonior/yubikey-cardano-wallet/blob/main/yubikey_load_keys.sh

