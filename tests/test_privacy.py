import os
import tempfile
from unittest.mock import patch

import numpy as np
import pytest
from PIL import Image, ImageDraw


@pytest.mark.parametrize(
    "category,sensitive_text",
    [
        ("Credit Card", "CREDIT CARD CODE: 1234 5678 9012 3456"),
        ("SSN / Govt ID", "SOCIAL SECURITY: 123 45 6789"),
        ("Bank IBAN", "BANK ACCOUNT: BE1234567890"),
        ("Password", "PASSWORD: SECRET123"),
        ("Medical Record", "MEDICAL DIAGNOSIS: CANCER STAGE 2 POSITIVE"),
        ("API Secret Key", "API KEY SECRET123456789"),
    ],
)
def test_sensitive_data_in_screenshot_is_masked(category, sensitive_text):
    img = Image.new("RGB", (800, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 40), sensitive_text, fill=(0, 0, 0))
    img_array = np.array(img)

    with tempfile.NamedTemporaryFile(delete=False) as tmp_db:
        db_path = tmp_db.name

    try:
        with patch("sys.argv", ["openrecall"]):
            with patch("openrecall.config.db_path", db_path):
                import openrecall.database as db
                from openrecall.screenshot import record_screenshots_thread

                db.db_path = db_path
                db.create_db()

                with patch("openrecall.screenshot.take_screenshots", return_value=[img_array]), \
                     patch("openrecall.screenshot.is_user_active", return_value=True), \
                     patch("openrecall.screenshot.is_similar", return_value=False), \
                     patch("openrecall.screenshot.get_active_app_name", return_value="TestApp"), \
                     patch("openrecall.screenshot.get_active_window_title", return_value="Privacy Window"), \
                     patch("time.sleep", side_effect=InterruptedError):
                    try:
                        record_screenshots_thread()
                    except InterruptedError:
                        pass

                entries = db.get_all_entries()
                assert len(entries) > 0, "No entry was recorded into the database."

                for entry in entries:
                    for keyword in sensitive_text.split():
                        assert keyword.lower() not in entry.text.lower(), (
                            f"Unmasked {category} keyword '{keyword}' found in database entry text: '{entry.text}'"
                        )
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass