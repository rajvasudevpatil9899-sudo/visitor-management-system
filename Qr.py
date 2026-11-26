
import qrcode
from PIL import Image, ImageDraw

# Enter QR code data
data = input("Enter text or URL: ")

# College logo file
logo_path = "gecalogo1.png"

# Create QR code with high error correction
qr = qrcode.QRCode(
    version=None,
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=12,
    border=4
)
qr.add_data(data)
qr.make(fit=True)

qr_img = qr.make_image(
    fill_color="black",
    back_color="white"
).convert("RGB")

# Open college logo
logo = Image.open(logo_path).convert("RGBA")

# Make logo larger (adjust 0.22 to change size)
logo_size = int(qr_img.width * 0.22)
logo.thumbnail((logo_size, logo_size))

# Create a clean white circular background
circle_size = int(qr_img.width * 0.28)
logo_bg = Image.new("RGBA", (circle_size, circle_size), (255, 255, 255, 0))
draw = ImageDraw.Draw(logo_bg)
draw.ellipse(
    (0, 0, circle_size - 1, circle_size - 1),
    fill="white"
)

# Centre logo inside the white circle
logo_position = (
    (circle_size - logo.width) // 2,
    (circle_size - logo.height) // 2
)
logo_bg.alpha_composite(logo, logo_position)

# Calculate exact centre of QR code
x = (qr_img.width - circle_size) // 2
y = (qr_img.height - circle_size) // 2

# Paste logo at the centre
qr_img.paste(logo_bg.convert("RGB"), (x, y))

# Save and display the QR code
qr_img.save("qr_with_college_logo.png")
qr_img.show()

print("QR code created successfully!")
print("Saved as qr_with_college_logo.png")
