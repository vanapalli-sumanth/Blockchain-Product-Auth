from web3 import Web3
import json
import os
from dotenv import load_dotenv

load_dotenv()

BLOCKCHAIN_PROVIDER = os.getenv("BLOCKCHAIN_PROVIDER")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS")

web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_PROVIDER))

if not web3.is_connected():
    raise Exception("Blockchain connection failed")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
abi_path = os.path.join(BASE_DIR, "contract_abi.json")

with open(abi_path, "r") as f:
    contract_abi = json.load(f)

contract = web3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=contract_abi
)

# =====================================================
# SEND TRANSACTION
# =====================================================

def send_transaction(function):

    try:

        wallet = Web3.to_checksum_address(WALLET_ADDRESS)

        nonce = web3.eth.get_transaction_count(wallet, "pending")

        block = web3.eth.get_block("latest")
        base_fee = block.get("baseFeePerGas", web3.to_wei(2, "gwei"))

        max_priority_fee = web3.to_wei(2, "gwei")
        max_fee = base_fee + max_priority_fee

        tx = function.build_transaction({

            "chainId": web3.eth.chain_id,
            "from": wallet,
            "nonce": nonce,
            "gas": 300000,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority_fee

        })

        signed_tx = web3.eth.account.sign_transaction(
            tx,
            PRIVATE_KEY
        )

        raw_tx = getattr(
            signed_tx,
            "rawTransaction",
            None
        ) or getattr(
            signed_tx,
            "raw_transaction"
        )

        tx_hash = web3.eth.send_raw_transaction(raw_tx)

        return web3.to_hex(tx_hash)

    except Exception as e:

        print("Transaction error:", e)

        return None


# =====================================================
# ADD PRODUCT
# =====================================================

def add_product(product_id, manufacturer, secure_token):

    tx_hash = send_transaction(

        contract.functions.addProduct(
            product_id,
            manufacturer,
            secure_token
        )

    )

    return tx_hash


# =====================================================
# VERIFY PRODUCT
# =====================================================

def verify_product(secure_token):

    try:

        result = contract.functions.verifyProduct(
            secure_token
        ).call()

        product_id = result[0]
        manufacturer = result[1]
        is_registered = result[2]

        return product_id, manufacturer, is_registered

    except Exception as e:

        print("Verify error:", e)

        return None, None, False