import io
import os
import time
from typing import List

import mss
import numpy as np
from cryptography.fernet import Fernet
from PIL import Image

from openrecall.config import args, screenshots_path, ENCRYPTION_KEY
from openrecall.database import insert_entry
from openrecall.nlp import get_embedding
from openrecall.ocr import extract_text_from_image
from openrecall.utils import get_active_app_name, get_active_window_title, is_user_active

cipher_suite = Fernet(ENCRYPTION_KEY)

def save_image(image: Image.Image, timestamp: int) -> str:
    filename = f"{timestamp}.webp"
    filepath = os.path.join(screenshots_path, filename)
    buffer = io.BytesIO()
    image.save(buffer, format="webp", lossless=True)
    encrypted_bytes = cipher_suite.encrypt(buffer.getvalue())
    with open(filepath, "wb") as f:
        f.write(encrypted_bytes)
    return filepath

def load_image(filepath: str) -> Image.Image:
    with open(filepath, "rb") as f:
        encrypted_bytes = f.read()
    decrypted_bytes = cipher_suite.decrypt(encrypted_bytes)
    buffer = io.BytesIO(decrypted_bytes)
    image = Image.open(buffer)
    image.load()
    return image


def mean_structured_similarity_index(
    img1: np.ndarray, img2: np.ndarray, L: int = 255
) -> float:
    """Calculates the Mean Structural Similarity Index (MSSIM) between two images."""
    K1, K2 = 0.01, 0.03
    C1, C2 = (K1 * L) ** 2, (K2 * L) ** 2

    def rgb2gray(img: np.ndarray) -> np.ndarray:
        return 0.2989 * img[..., 0] + 0.5870 * img[..., 1] + 0.1140 * img[..., 2]

    img1_gray: np.ndarray = rgb2gray(img1)
    img2_gray: np.ndarray = rgb2gray(img2)
    mu1: float = np.mean(img1_gray)
    mu2: float = np.mean(img2_gray)
    sigma1_sq = np.var(img1_gray)
    sigma2_sq = np.var(img2_gray)
    sigma12 = np.mean((img1_gray - mu1) * (img2_gray - mu2))
    ssim_index = ((2 * mu1 * mu2 + C1) * (2 * sigma12 + C2)) / (
        (mu1**2 + mu2**2 + C1) * (sigma1_sq + sigma2_sq + C2)
    )
    return ssim_index


def is_similar(
    img1: np.ndarray, img2: np.ndarray, similarity_threshold: float = 0.9
) -> bool:
    """Checks if two images are similar based on MSSIM."""
    similarity: float = mean_structured_similarity_index(img1, img2)
    return similarity >= similarity_threshold


def take_screenshots() -> List[np.ndarray]:
    """Takes screenshots of all connected monitors or just the primary one."""
    screenshots: List[np.ndarray] = []
    with mss.mss() as sct:
        monitor_indices = range(1, len(sct.monitors))

        if args.primary_monitor_only:
            monitor_indices = [1]

        for i in monitor_indices:
            if i < len(sct.monitors):
                monitor_info = sct.monitors[i]
                sct_img = sct.grab(monitor_info)
                screenshot = np.array(sct_img)[:, :, [2, 1, 0]]
                screenshots.append(screenshot)
            else:
                print(f"Warning: Monitor index {i} out of bounds. Skipping.")

    return screenshots

def record_screenshots_thread() -> None:
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    last_screenshots: List[np.ndarray] = take_screenshots()

    while True:
        if not is_user_active():
            time.sleep(3)
            continue

        current_screenshots: List[np.ndarray] = take_screenshots()
        if len(last_screenshots) != len(current_screenshots):
            last_screenshots = current_screenshots
            time.sleep(3)
            continue

        for i, current_screenshot in enumerate(current_screenshots):
            last_screenshot = last_screenshots[i]
            if not is_similar(current_screenshot, last_screenshot):
                last_screenshots[i] = current_screenshot
                image = Image.fromarray(current_screenshot)
                timestamp = int(time.time())
                save_image(image, timestamp)
                text: str = extract_text_from_image(current_screenshot)
                if text.strip():
                    embedding: np.ndarray = get_embedding(text)
                    active_app_name: str = get_active_app_name() or "Unknown App"
                    active_window_title: str = get_active_window_title() or "Unknown Title"
                    insert_entry(text, timestamp, embedding, active_app_name, active_window_title)

        time.sleep(3)