from web3 import Web3
import json
import os
from dotenv import load_dotenv

# =========================================================
# LOAD ENV VARIABLES
# =========================================================

load_dotenv()

BLOCKCHAIN_PROVIDER = os.getenv("BLOCKCHAIN_PROVIDER")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS")

if not BLOCKCHAIN_PROVIDER or not CONTRACT_ADDRESS or not PRIVATE_KEY or not WALLET_ADDRESS:
    raise Exception("❌ Missing blockchain environment variables")

# =========================================================
# CONNECT TO SEPOLIA VIA INFURA
# =========================================================

web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_PROVIDER))

if not web3.is_connected():
    raise Exception("❌ Blockchain connection failed")

print("✅ Connected to Sepolia Cloud Blockchain")
print("🌐 Chain ID:", web3.eth.chain_id)

# =========================================================
# LOAD CONTRACT ABI
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
abi_path = os.path.join(BASE_DIR, "contract_abi.json")

if not os.path.exists(abi_path):
    raise Exception("❌ contract_abi.json not found")

with open(abi_path, "r") as f:
    contract_abi = json.load(f)

contract = web3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=contract_abi
)

# =========================================================
# SEND SIGNED TRANSACTION (EIP-1559 SAFE)
# =========================================================

def send_transaction(function):

    try:

        wallet = Web3.to_checksum_address(WALLET_ADDRESS)

        # Always use pending nonce (IMPORTANT)
        nonce = web3.eth.get_transaction_count(wallet, "pending")

        # Get latest block base fee
        block = web3.eth.get_block("latest")
        base_fee = block.get("baseFeePerGas", web3.to_wei(2, "gwei"))

        max_priority_fee = web3.to_wei(2, "gwei")
        max_fee = base_fee + max_priority_fee

        # Build transaction
        transaction = function.build_transaction({
            "chainId": web3.eth.chain_id,
            "from": wallet,
            "nonce": nonce,
            "gas": 200000,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority_fee,
        })

        # Sign transaction
        signed_tx = web3.eth.account.sign_transaction(
            transaction,
            PRIVATE_KEY
        )

        # Web3 v5 + v6 compatibility
        raw_tx = getattr(signed_tx, "rawTransaction", None) or getattr(signed_tx, "raw_transaction")

        # Send transaction
        tx_hash = web3.eth.send_raw_transaction(raw_tx)

        tx_hex = web3.to_hex(tx_hash)

        print("✅ Transaction sent:", tx_hex)

        return tx_hex

    except Exception as e:

        print("❌ Transaction error:", str(e))

        return None


# =========================================================
# ADD PRODUCT TO BLOCKCHAIN
# =========================================================

def add_product(product_id, manufacturer,secure_token):

    print("📦 Adding product to blockchain:", product_id)

    return send_transaction(
        contract.functions.addProduct(
            product_id,
            manufacturer,
            secure_token
        )
    )


# =========================================================
# VERIFY PRODUCT FROM BLOCKCHAIN
# =========================================================

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

print("Contract address:", CONTRACT_ADDRESS)
print("Chain ID:", web3.eth.chain_id)
