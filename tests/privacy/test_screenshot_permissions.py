import os
import pytest
import numpy as np
from PIL import Image, UnidentifiedImageError

import openrecall.screenshot as screenshot_module

def test_third_party_cannot_read_saved_screenshot(tmp_path, monkeypatch):
    # 1. Arrange
    test_screenshots_dir = tmp_path / "screenshots"
    test_screenshots_dir.mkdir()
    monkeypatch.setattr(screenshot_module, "screenshots_path", str(test_screenshots_dir))

    dummy_array = np.zeros((100, 100, 3), dtype=np.uint8)
    image = Image.fromarray(dummy_array)
    timestamp = 123456789

    # 2. Act: Gebruik de echte save_image uit de module
    filepath = screenshot_module.save_image(image, timestamp)

    # 3. Assert: 3rd party lezer (zoals een normale PIL.Image.open) faalt
    with pytest.raises(UnidentifiedImageError):
        with Image.open(filepath) as img:
            img.verify()

def test_app_can_decrypt_and_load_screenshot(tmp_path, monkeypatch):
    test_screenshots_dir = tmp_path / "screenshots"
    test_screenshots_dir.mkdir()
    monkeypatch.setattr(screenshot_module, "screenshots_path", str(test_screenshots_dir))

    # 1. Gebruik een afbeelding met herkenbare pixeldata (niet alleen nullen)
    dummy_array = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    original_image = Image.fromarray(dummy_array)
    timestamp = 123456789

    # 2. Opslaan en weer inladen
    filepath = screenshot_module.save_image(original_image, timestamp)
    loaded_image = screenshot_module.load_image(filepath)

    # 3. Zorg dat de afbeeldingsmodi (bv. RGB) overeenkomen
    loaded_image = loaded_image.convert("RGB")

    # 4. Assertie op de EXACTE pixeldata
    original_pixels = np.array(original_image)
    loaded_pixels = np.array(loaded_image)

    # Bij lossless WebP moeten alle pixels exact identiek zijn:
    np.testing.assert_array_equal(original_pixels, loaded_pixels)