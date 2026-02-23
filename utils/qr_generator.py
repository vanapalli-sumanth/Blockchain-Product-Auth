import qrcode
import os
import hashlib
from utils.token_generator import create_secure_token
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFont

load_dotenv()

BASE_URL = os.getenv("BASE_VERIFY_URL")


def generate_qr(unit_id, scratch_code):

    secure_token = create_secure_token().strip()

    signature = hashlib.sha256(
        f"{unit_id}:{secure_token}".encode()
    ).hexdigest().strip()

    scan_url = f"{BASE_URL}/s/{signature}"

    folder = "static/qr_codes"
    os.makedirs(folder, exist_ok=True)

    file_path = f"{folder}/{unit_id}.png"

    # Generate QR image
    qr = qrcode.QRCode(
        version=1,
        box_size=8,
        border=2
    )

    qr.add_data(scan_url)
    qr.make(fit=True)

    qr_img = qr.make_image(
        fill_color="black",
        back_color="white"
    ).convert("RGB")

    # Create new image with extra space for scratch code
    width, height = qr_img.size
    extra_height = 40

    new_img = Image.new(
        "RGB",
        (width, height + extra_height),
        "white"
    )

    new_img.paste(qr_img, (0, 0))

    # Draw scratch text
    draw = ImageDraw.Draw(new_img)

    try:
        font = ImageFont.truetype("arial.ttf", 14)
    except:
        font = ImageFont.load_default()

    text = f"Scratch: {scratch_code}"

    text_width = draw.textlength(text, font=font)

    x = (width - text_width) // 2
    y = height + 10

    draw.text(
        (x, y),
        text,
        fill="black",
        font=font
    )

    # Save final image
    new_img.save(file_path)

    return {
        "secure_token": secure_token,
        "signature": signature,
        "qr_path": f"qr_codes/{unit_id}.png"
    }