import random
from PIL import Image, ImageDraw, ImageFont
import io
import base64

def generate_captcha_image():
    """Generate a CAPTCHA image with random text"""
    # Create image
    width, height = 200, 80
    image = Image.new('RGB', (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)
    
    # Generate random text
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    captcha_text = ''.join(random.choice(chars) for _ in range(6))
    
    # Draw text
    try:
        font = ImageFont.truetype('arial.ttf', 36)
    except:
        font = ImageFont.load_default()
    
    for i, char in enumerate(captcha_text):
        x = 20 + i * 30 + random.randint(-5, 5)
        y = 10 + random.randint(-10, 10)
        angle = random.randint(-20, 20)
        
        # Draw each character with slight variations
        temp_img = Image.new('RGBA', (40, 60), (0, 0, 0, 0))
        temp_draw = ImageDraw.Draw(temp_img)
        temp_draw.text((10, 10), char, fill=(0, 0, 0), font=font)
        temp_img = temp_img.rotate(angle, expand=1)
        
        image.paste(temp_img, (x, y), temp_img)
    
    # Add noise
    for _ in range(100):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))
    
    # Convert to base64 for easy embedding in Tkinter
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return captcha_text, f"data:image/png;base64,{img_str}"