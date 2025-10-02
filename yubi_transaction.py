from pycardano import *
import json
import os
import sys
import subprocess
from blockfrost import ApiUrls
import getpass


cwd = os.getcwd()


with open(cwd + '/generated/keys/ed25519_pub.hex') as f:
        ed25519_pub_hex = f.read().strip()
BF_PROJ_ID = getpass.getpass("enter blockfrost preview API key:")

payment_vkey = PaymentVerificationKey(bytes.fromhex(ed25519_pub_hex))
print(payment_vkey)
address = Address(payment_vkey.hash(),payment_vkey.hash(),network=Network.TESTNET)
print(address)
chain_context = BlockFrostChainContext(project_id=BF_PROJ_ID,base_url=ApiUrls.preview.value,)
utxos = chain_context.utxos(address)
balance = 0
for n in utxos:
        balance += n.output.amount.coin

print(f'wallet has {len(utxos)} UTxOs and {round((balance/1000000),2)} ADA')

builder = TransactionBuilder(chain_context)
builder.add_input_address(address)
builder.add_output(TransactionOutput(address,Value(1500000)))

#unsignedTx = builder.build_and_sign([], change_address=address)
unsignedTx = builder.build(change_address=address)
        #chain_context.submit_tx(signed_tx.to_cbor())
#print(signed_tx.transaction_body.hash().hex())
tbody_hash_hex = unsignedTx.hash().hex()
#tbody_hash_hex = unsignedTx.transaction_body.hash().hex()
print(tbody_hash_hex)

#sys.exit()
script_path = "./yubi_sign.sh"

pin = getpass.getpass(prompt='Enter your YubiKey PIN or password: ')


try:
    # Run the Bash script with arguments
    signature = subprocess.run(
        [script_path, pin, tbody_hash_hex],
        capture_output=True,
        text=True,
        check=True
    )


    # Check if output is empty

    if not signature.stdout:
        raise ValueError("No output returned from script")
    # Print the signature (hex string)
    print('Signed Tx body hash!\n')
    print(signature.stdout)

except subprocess.CalledProcessError as e:
    # Handle script errors (non-zero exit code)
    print(f"Error running script: {e.stderr}")
    sys.exit(1)
except ValueError as e:
    # Handle empty output
    print(f"Error: {e}")
    sys.exit(1)
except FileNotFoundError:
    # Handle script not found
    print(f"Error: Script {script_path} not found")
    sys.exit(1)


vk_witnesses = [VerificationKeyWitness(payment_vkey, bytes.fromhex(signature.stdout.strip()))]
signed_tx = Transaction(unsignedTx, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

print(signed_tx.transaction_body)
chain_context.submit_tx(signed_tx.to_cbor())
print(signed_tx.id)
