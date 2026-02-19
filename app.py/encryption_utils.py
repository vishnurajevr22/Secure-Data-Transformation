
from stegano import lsb

def hide_text_in_image(input_image_path, secret_text, output_image_path):
    # Hides the secret text inside input image and saves to output image
    secret_image = lsb.hide(input_image_path, secret_text)
    secret_image.save(output_image_path)

def reveal_text_from_image(stego_image_path):
    # Extracts the hidden text from the image
    secret_text = lsb.reveal(stego_image_path)
    return secret_text
