import unittest
from unittest.mock import patch

try:
    import httpx
    from fastapi import HTTPException
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from api import images as images_api
    from database import Base
    from models import ImageCache

    DEPS_AVAILABLE = True
except ModuleNotFoundError:
    DEPS_AVAILABLE = False


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 32
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def _client(body: bytes, content_type: str | None):
    def handler(_request):
        headers = {"content-type": content_type} if content_type else {}
        return httpx.Response(200, content=body, headers=headers)

    return httpx.Client(transport=httpx.MockTransport(handler))


@unittest.skipUnless(DEPS_AVAILABLE, "Backend dependencies are not installed")
class CatalogueImageFetchTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()

    def tearDown(self):
        self.db.close()

    def _fetch(self, body, content_type, key="k"):
        with patch.object(images_api, "_client", _client(body, content_type)):
            return images_api._get_or_fetch(self.db, key, "https://assets.example/x.webp")

    def test_declared_raster_type_is_kept(self):
        data, content_type = self._fetch(PNG, "image/png")
        self.assertEqual((data, content_type), (PNG, "image/png"))

    def test_generic_type_is_resolved_from_magic_bytes(self):
        _, content_type = self._fetch(WEBP, "application/octet-stream")
        self.assertEqual(content_type, "image/webp")

    def test_svg_is_never_cached_or_served(self):
        for declared in ("image/svg+xml", "application/octet-stream", None):
            with self.assertRaises(HTTPException):
                self._fetch(SVG, declared, key=f"svg-{declared}")
        self.assertEqual(self.db.query(ImageCache).count(), 0)

    def test_oversized_upstream_image_is_refused(self):
        with patch.object(images_api, "_MAX_UPSTREAM_IMAGE_BYTES", 16):
            with self.assertRaises(HTTPException):
                self._fetch(PNG, "image/png")


@unittest.skipUnless(DEPS_AVAILABLE, "Backend dependencies are not installed")
class ImageResponseHeaderTests(unittest.TestCase):
    def test_proxied_images_are_sandboxed_and_not_sniffed(self):
        response = images_api._image_response(PNG, "image/png", "public, max-age=60")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertIn("sandbox", response.headers["content-security-policy"])
        self.assertEqual(response.headers["cache-control"], "public, max-age=60")


if __name__ == "__main__":
    unittest.main()
