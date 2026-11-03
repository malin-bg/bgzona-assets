"""Inactive image-only privacy gate R1. No filesystem, Git, staging or publishing API.

Contract: prepare(immutable bytes, extension, role='original'|'og') returns a
JSON-safe evidence record plus output bytes ONLY on SANITIZED_AND_VERIFIED.
That status certifies this bounded container policy, NEVER publication authority.
Future type-specific modules must use the same four statuses and bind results to
exact input/output hashes and policy/tool versions; unsupported means no clearance.

Policy: no re-encoding. Keep compressed image data, palettes, alpha, frame controls
and recognized numeric color information. Remove JPEG EXIF/XMP/COM/JFIF thumbnails/
IPTC-only Photoshop resources; PNG text/time/eXIf; WebP EXIF/XMP; GIF comments.
Unknown semantic blocks, ICC (including descriptive fields) and nontrivial EXIF
orientation require review. Never discard essential ICC or rotate/recompress.
No claims about visible secrets, steganography, filenames, Git identities or all
metadata formats. Byte identity and decoding comparisons are necessary, not a
complete anonymity proof. No hooks/worker/boundary is installed by this module.
"""
from dataclasses import dataclass
from io import BytesIO
import platform
import struct
import warnings
import zlib

from PIL import Image, __version__ as pillow_version, features
from importer import EXTS, Reject, data, digest, probe

POLICY = 'bgzona-image-privacy-r1'
MAX_BYTES = 50_000_000
MAX_BLOCKS = 100_000
STATUSES = ('SANITIZED_AND_VERIFIED', 'NEEDS_REVIEW', 'REJECTED', 'UNSUPPORTED')


class GateError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def fail(code, status='REJECTED'):
    raise GateError(status, code)


def review(code):
    fail(code, 'NEEDS_REVIEW')


def unsupported(code):
    fail(code, 'UNSUPPORTED')


@dataclass(frozen=True)
class Result:
    # Evidence never contains input names, metadata values, or raw image bytes.
    evidence: dict
    output: bytes | None = None


def tools():
    return {'python': platform.python_version(), 'Pillow': pillow_version,
            'jpeg': features.version('jpg'), 'webp': features.version('webp'),
            'zlib': features.version('zlib'),
            'littlecms2': features.version('littlecms2')}


def orientation(b):
    """Read only IFD0 orientation before removing the whole EXIF container."""
    if b.startswith(b'Exif\0\0'):
        b = b[6:]
    if len(b) < 8 or b[:2] not in (b'II', b'MM'):
        fail('MALFORMED_EXIF')
    order = '<' if b[:2] == b'II' else '>'
    u16 = lambda p: struct.unpack_from(order + 'H', b, p)[0]
    u32 = lambda p: struct.unpack_from(order + 'I', b, p)[0]
    if u16(2) != 42:
        fail('MALFORMED_EXIF')
    p = u32(4)
    if p < 8 or p + 2 > len(b):
        fail('MALFORMED_EXIF')
    count = u16(p)
    if count > 4096 or p + 2 + count * 12 + 4 > len(b):
        fail('MALFORMED_EXIF')
    seen = False
    for n in range(count):
        q = p + 2 + n * 12
        if u16(q) == 274:
            if seen or u16(q + 2) != 3 or u32(q + 4) != 1:
                fail('AMBIGUOUS_ORIENTATION')
            seen = True
            v = u16(q + 8)
            if v not in range(1, 9):
                fail('INVALID_ORIENTATION')
            if v != 1:
                review('ORIENTATION_REQUIRES_LOSSLESS_TRANSFORM')


def xmp(b):
    # XMP rendering orientation must not disappear silently.
    if b'orientation' in b.lower():
        review('XMP_ORIENTATION_REQUIRES_REVIEW')


def photoshop(b):
    if not b.startswith(b'Photoshop 3.0\0'):
        review('UNKNOWN_APP13')
    p = 14
    if p == len(b):
        return
    while p < len(b):
        if b[p:p + 4] != b'8BIM' or p + 7 > len(b):
            fail('MALFORMED_PHOTOSHOP')
        resource = int.from_bytes(b[p + 4:p + 6], 'big')
        p += 6
        name_size = 1 + b[p]
        p += name_size + name_size % 2
        if p + 4 > len(b):
            fail('MALFORMED_PHOTOSHOP')
        size = int.from_bytes(b[p:p + 4], 'big')
        p += 4
        if p + size + size % 2 > len(b):
            fail('MALFORMED_PHOTOSHOP')
        if resource != 0x0404:
            review('PHOTOSHOP_NON_IPTC_RESOURCE')
        p += size + size % 2


def jpeg(b):
    if not b.startswith(b'\xff\xd8'):
        fail('JPEG_SIGNATURE')
    out, technical, removed = [b[:2]], [b[:2]], []
    p, scans, blocks = 2, 0, 0
    while p < len(b):
        blocks += 1
        if blocks > MAX_BLOCKS or b[p] != 255:
            fail('JPEG_STRUCTURE')
        start = p
        while p < len(b) and b[p] == 255:
            p += 1
        if p == len(b):
            fail('JPEG_TRUNCATED')
        marker = b[p]
        p += 1
        if marker == 0xD9:
            if p != len(b) or not scans:
                fail('JPEG_TRAILING_OR_EMPTY')
            out.append(b[start:p])
            technical.append(b[start:p])
            return b''.join(out), digest(b''.join(technical)), removed
        if marker in (0, 0xD8, 1) or 0xD0 <= marker <= 0xD7:
            fail('JPEG_UNEXPECTED_MARKER')
        if p + 2 > len(b):
            fail('JPEG_TRUNCATED')
        size = int.from_bytes(b[p:p + 2], 'big')
        end = p + size
        if size < 2 or end > len(b):
            fail('JPEG_LENGTH')
        payload, segment = b[p + 2:end], b[start:end]
        p = end
        keep = True
        if marker == 0xE0:
            if payload.startswith(b'JFIF\0'):
                if len(payload) < 14:
                    fail('JFIF_LENGTH')
                x, y = payload[12:14]
                if len(payload) != 14 + 3 * x * y:
                    fail('JFIF_THUMBNAIL_LENGTH')
                # Keep technical version, units, density/aspect exactly.
                new = payload[:12] + b'\0\0'
                segment = b'\xff\xe0' + (len(new) + 2).to_bytes(2, 'big') + new
                if x or y:
                    removed.append('JFIF_THUMBNAIL')
            elif payload.startswith(b'JFXX\0'):
                keep = False
                removed.append('JFXX_THUMBNAIL')
            else:
                review('UNKNOWN_APP0')
        elif marker == 0xEE:
            if len(payload) != 12 or payload[:5] != b'Adobe' or payload[-1] > 2:
                review('UNKNOWN_ADOBE_COLOR')
        elif marker == 0xE1:
            keep = False
            if payload.startswith(b'Exif\0\0'):
                orientation(payload)
                removed.append('EXIF')
            elif payload.startswith(b'http://ns.adobe.com/xap/1.0/\0'):
                xmp(payload)
                removed.append('XMP')
            else:
                review('UNKNOWN_APP1')
        elif marker == 0xE2:
            review('ICC_OR_OTHER_APP2')
        elif marker == 0xED:
            photoshop(payload)
            keep = False
            removed.append('IPTC')
        elif marker == 0xFE:
            keep = False
            removed.append('COMMENT')
        elif 0xE0 <= marker <= 0xEF:
            review('UNKNOWN_JPEG_APPLICATION')
        elif marker not in (0xC0, 0xC1, 0xC2, 0xC4, 0xDB, 0xDD, 0xDA):
            unsupported('JPEG_PROCESS')
        if keep:
            out.append(segment)
            technical.append(segment)
        if marker == 0xDA:
            scans += 1
            q = p
            while q < len(b):
                if b[q] != 255:
                    q += 1
                    continue
                r = q + 1
                while r < len(b) and b[r] == 255:
                    r += 1
                if r == len(b):
                    fail('JPEG_TRUNCATED_SCAN')
                if b[r] == 0 or 0xD0 <= b[r] <= 0xD7:
                    q = r + 1
                    continue
                break
            out.append(b[p:q])
            technical.append(b[p:q])
            p = q
    fail('JPEG_MISSING_EOI')


PNG_SIG = b'\x89PNG\r\n\x1a\n'
PNG_KEEP = {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS',
            b'gAMA', b'cHRM', b'sRGB', b'sBIT', b'bKGD', b'hIST'}


def png(b):
    if not b.startswith(PNG_SIG):
        fail('PNG_SIGNATURE')
    p, count, image, end_seen = 8, 0, False, False
    seen, palette_size, idat_closed = set(), None, False
    inflater, expanded, expansion_limit = zlib.decompressobj(), 0, 0
    out, technical, removed = [PNG_SIG], [PNG_SIG], []
    while p < len(b):
        count += 1
        if count > MAX_BLOCKS or p + 12 > len(b):
            fail('PNG_LENGTH')
        n = int.from_bytes(b[p:p + 4], 'big')
        kind = b[p + 4:p + 8]
        end = p + 12 + n
        if end > len(b):
            fail('PNG_LENGTH')
        content = b[p + 8:end - 4]
        if zlib.crc32(kind + content) != int.from_bytes(b[end - 4:end], 'big'):
            fail('PNG_CRC')
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind) or kind[2] & 32:
            fail('PNG_CHUNK_TYPE')
        if count == 1 and (kind != b'IHDR' or n != 13):
            fail('PNG_IHDR')
        if kind == b'IHDR' and count != 1:
            fail('PNG_DUPLICATE_IHDR')
        if kind != b'IDAT' and image:
            idat_closed = True
        if kind in PNG_KEEP - {b'IDAT'} and kind in seen:
            fail('PNG_DUPLICATE_TECHNICAL_CHUNK')
        seen.add(kind)
        if kind == b'IHDR':
            width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', content)
            if not width or not height or width * height > 40_000_000:
                fail('IMAGE_LIMIT')
            expansion_limit = min(400_000_000, (width * 8 + 8) * height + 1024)
        if kind in {b'gAMA', b'cHRM', b'sRGB'}:
            required = {b'gAMA': 4, b'cHRM': 32, b'sRGB': 1}[kind]
            if n != required:
                fail('PNG_COLOR_LENGTH')
            if kind == b'sRGB' and content[0] > 3:
                fail('PNG_SRGB_INTENT')
            if kind == b'gAMA' and not int.from_bytes(content, 'big'):
                fail('PNG_GAMMA')
        if kind == b'PLTE':
            if not n or n > 768 or n % 3 or image:
                fail('PNG_PALETTE_LENGTH')
            palette_size = n // 3
        if kind == b'sBIT':
            if n != {0: 1, 2: 3, 3: 3, 4: 2, 6: 4}.get(color):
                fail('PNG_SBIT_LENGTH')
            if any(v < 1 or v > (8 if color == 3 else depth) for v in content):
                fail('PNG_SBIT_VALUE')
        if kind == b'bKGD' and n != (1 if color == 3 else 2 if color in (0, 4) else 6):
            fail('PNG_BACKGROUND_LENGTH')
        if kind == b'hIST' and (palette_size is None or n != 2 * palette_size):
            fail('PNG_HISTOGRAM_LENGTH')
        if kind == b'tRNS':
            if color == 3:
                if palette_size is None or not 1 <= n <= palette_size:
                    fail('PNG_TRANSPARENCY_LENGTH')
            elif n != {0: 2, 2: 6}.get(color):
                fail('PNG_TRANSPARENCY_LENGTH')
        if kind == b'IDAT':
            if idat_closed:
                fail('PNG_NONCONTIGUOUS_IMAGE_DATA')
            image = True
            pending = content
            while pending:
                decoded_part = inflater.decompress(pending, 65536)
                expanded += len(decoded_part)
                if expanded > expansion_limit:
                    fail('PNG_EXPANSION_LIMIT')
                if inflater.unused_data:
                    fail('PNG_HIDDEN_COMPRESSED_TRAILING_DATA')
                pending = inflater.unconsumed_tail
        if kind == b'IEND':
            if n or end != len(b) or not image:
                fail('PNG_TRAILING_OR_EMPTY')
            end_seen = True
        keep = kind in PNG_KEEP
        if not keep:
            if kind in (b'tEXt', b'zTXt', b'iTXt', b'tIME'):
                removed.append(kind.decode('ascii'))
            elif kind == b'eXIf':
                orientation(content)
                removed.append('EXIF')
            elif kind == b'iCCP':
                review('ICC_REQUIRES_COLOR_REVIEW')
            elif kind == b'pHYs':
                if n != 9:
                    fail('PNG_PHYS_LENGTH')
                if content[:4] != content[4:8]:
                    review('PNG_NON_SQUARE_PIXEL_ASPECT')
                removed.append('DENSITY')
            elif kind in (b'acTL', b'fcTL', b'fdAT'):
                unsupported('APNG_NOT_SUPPORTED')
            elif kind[0] & 32:
                review('UNKNOWN_PNG_ANCILLARY')
            else:
                unsupported('UNKNOWN_PNG_CRITICAL')
        if keep:
            out.append(b[p:end])
            technical.append(b[p:end])
        p = end
    if not end_seen:
        fail('PNG_MISSING_IEND')
    if not inflater.eof or inflater.unused_data:
        fail('PNG_INCOMPLETE_COMPRESSED_STREAM')
    return b''.join(out), digest(b''.join(technical)), removed


def riff_chunks(b, start, stop):
    p, count = start, 0
    while p < stop:
        count += 1
        if count > MAX_BLOCKS or p + 8 > stop:
            fail('WEBP_CHUNK_LENGTH')
        n = int.from_bytes(b[p + 4:p + 8], 'little')
        end = p + 8 + n + (n & 1)
        if end > stop or (n & 1 and b[end - 1] != 0):
            fail('WEBP_CHUNK_PADDING')
        yield b[p:p + 4], b[p + 8:p + 8 + n], b[p:end]
        p = end


def webp(b):
    if len(b) < 12 or b[:4] != b'RIFF' or b[8:12] != b'WEBP':
        fail('WEBP_SIGNATURE')
    if int.from_bytes(b[4:8], 'little') + 8 != len(b):
        fail('WEBP_TRAILING_OR_LENGTH')
    out, technical, removed = [], [], []
    seen = set()
    for kind, content, raw in riff_chunks(b, 12, len(b)):
        if kind != b'ANMF' and kind in seen:
            fail('WEBP_DUPLICATE_CHUNK')
        seen.add(kind)
        if kind == b'VP8X':
            if out or len(content) != 10 or content[0] & 0xC1 or content[1:4] != b'\0\0\0':
                fail('WEBP_VP8X')
            if content[0] & 0x20:
                review('ICC_REQUIRES_COLOR_REVIEW')
            content = bytes([content[0] & ~0x0C]) + content[1:]
            raw = b'VP8X' + (10).to_bytes(4, 'little') + content
        elif kind == b'EXIF':
            orientation(content)
            removed.append('EXIF')
            continue
        elif kind == b'XMP ':
            xmp(content)
            removed.append('XMP')
            continue
        elif kind == b'ICCP':
            review('ICC_REQUIRES_COLOR_REVIEW')
        elif kind == b'ANIM':
            if len(content) != 6:
                fail('WEBP_ANIM_LENGTH')
        elif kind == b'ANMF':
            if len(content) < 24 or content[15] & 0xFC:
                fail('WEBP_ANMF_HEADER')
            nested = list(riff_chunks(content, 16, len(content)))
            if not nested or any(k not in (b'ALPH', b'VP8 ', b'VP8L') for k, _, _ in nested):
                review('WEBP_FRAME_UNKNOWN_DATA')
            if sum(k in (b'VP8 ', b'VP8L') for k, _, _ in nested) != 1:
                fail('WEBP_FRAME_IMAGE_COUNT')
        elif kind not in (b'VP8 ', b'VP8L', b'ALPH'):
            review('UNKNOWN_WEBP_CHUNK')
        out.append(raw)
        technical.append(raw)
    if not seen.intersection((b'VP8 ', b'VP8L', b'ANMF')):
        fail('WEBP_MISSING_IMAGE')
    body = b'WEBP' + b''.join(out)
    return b'RIFF' + len(body).to_bytes(4, 'little') + body, digest(b''.join(technical)), removed


def subblocks(b, p):
    start, parts = p, []
    while True:
        if p >= len(b):
            fail('GIF_TRUNCATED_BLOCK')
        n = b[p]
        p += 1
        if not n:
            return p, b[start:p], b''.join(parts)
        if p + n > len(b):
            fail('GIF_TRUNCATED_BLOCK')
        parts.append(b[p:p + n])
        p += n


def gif(b):
    if len(b) < 13 or b[:6] not in (b'GIF87a', b'GIF89a'):
        fail('GIF_SIGNATURE')
    p = 13 + (3 * (2 ** ((b[10] & 7) + 1)) if b[10] & 128 else 0)
    if p > len(b):
        fail('GIF_PALETTE')
    out, technical, removed = [b[:p]], [b[:p]], []
    frames, blocks, loop_seen = 0, 0, False
    while p < len(b):
        blocks += 1
        if blocks > MAX_BLOCKS:
            fail('GIF_BLOCK_LIMIT')
        start, kind = p, b[p]
        p += 1
        if kind == 0x3B:
            if p != len(b) or not frames:
                fail('GIF_TRAILING_OR_EMPTY')
            out.append(b[start:p])
            technical.append(b[start:p])
            return b''.join(out), digest(b''.join(technical)), removed
        if kind == 0x2C:
            if p + 9 > len(b):
                fail('GIF_DESCRIPTOR')
            packed = b[p + 8]
            p += 9
            if packed & 128:
                p += 3 * 2 ** ((packed & 7) + 1)
            if p >= len(b) or not 2 <= b[p] <= 8:
                fail('GIF_LZW_CODE_SIZE')
            p, _, _ = subblocks(b, p + 1)
            frames += 1
        elif kind == 0x21:
            if p >= len(b):
                fail('GIF_EXTENSION')
            label = b[p]
            p += 1
            if label == 0xFE:
                p, _, _ = subblocks(b, p)
                removed.append('COMMENT')
                continue
            if label == 0xF9:
                if p + 6 > len(b) or b[p] != 4 or b[p + 5] != 0:
                    fail('GIF_GCE')
                if b[p + 1] & 0xE0 or (b[p + 1] >> 2) & 7 > 3:
                    unsupported('GIF_RESERVED_DISPOSAL')
                p += 6
            elif label == 0xFF:
                if p + 12 > len(b) or b[p] != 11:
                    fail('GIF_APPLICATION')
                app = b[p + 1:p + 12]
                p, encoded, payload = subblocks(b, p + 12)
                if app in (b'NETSCAPE2.0', b'ANIMEXTS1.0'):
                    if loop_seen or len(payload) != 3 or payload[0] != 1 or encoded[0] != 3:
                        fail('GIF_LOOP_EXTENSION')
                    loop_seen = True
                elif app == b'ICCRGBG1012':
                    review('ICC_REQUIRES_COLOR_REVIEW')
                else:
                    review('UNKNOWN_GIF_APPLICATION')
            elif label == 1:
                unsupported('GIF_PLAIN_TEXT_RENDERING')
            else:
                review('UNKNOWN_GIF_EXTENSION')
        else:
            fail('GIF_STRUCTURE')
        out.append(b[start:p])
        technical.append(b[start:p])
    fail('GIF_MISSING_TRAILER')


FILTERS = {'JPEG': jpeg, 'PNG': png, 'WEBP': webp, 'GIF': gif}


def decoded(b):
    """Independent Pillow decoder: all composited frames and technical semantics."""
    with warnings.catch_warnings():
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(BytesIO(b)) as im:
            result = {'format': im.format, 'size': list(im.size), 'frames': [],
                      'loop': im.info.get('loop')}
            for n in range(getattr(im, 'n_frames', 1)):
                im.seek(n)
                im.load()
                result['frames'].append({
                    'rgba': digest(im.convert('RGBA').tobytes()),
                    'duration_ms': im.info.get('duration'),
                    'disposal': getattr(im, 'disposal_method', None)})
            return result


def verify_output(source, candidate, ext, role, fmt, technical_hash):
    # Fresh container inspection + separately implemented decoder, not tool exit.
    clean, output_technical, removed = FILTERS[fmt](candidate)
    if clean != candidate or removed or output_technical != technical_hash:
        fail('OUTPUT_CONTAINER_VERIFICATION')
    inspected = probe(candidate, ext, og=role == 'og')
    a, b = decoded(source), decoded(candidate)
    if a != b:
        review('DECODED_APPEARANCE_CHANGED')
    # Defense in depth against fields recognized by the independent decoder.
    with Image.open(BytesIO(candidate)) as im:
        allowed = {'JPEG': {'jfif', 'jfif_version', 'jfif_unit', 'jfif_density',
                            'dpi', 'adobe', 'adobe_transform', 'progressive', 'progression'},
                   'PNG': {'transparency', 'gamma', 'chromaticity', 'srgb',
                           'bits', 'background'},
                   'WEBP': {'loop', 'background', 'duration', 'timestamp'},
                   'GIF': {'version', 'background', 'transparency', 'duration',
                           'loop', 'extension'}}[fmt]
        for n in range(getattr(im, 'n_frames', 1)):
            im.seek(n)
            im.load()
            if set(im.info) - allowed or im.getexif():
                review('DECODER_UNEXPECTED_METADATA')
            if 'extension' in im.info and im.info['extension'][0] not in (
                    b'NETSCAPE2.0', b'ANIMEXTS1.0'):
                review('DECODER_UNKNOWN_EXTENSION')
    return inspected, digest(data(b)), a


def prepare(raw, extension, role='original'):
    """Pure bytes transaction; no result payload on failure, no public permission.

    Caller must hold a trusted private snapshot, check exact digest at handoff,
    preserve private originals/backups and enforce the publication boundary.
    This module deliberately does not implement that future integration.
    """
    evidence = {'policy': POLICY, 'tools': tools(), 'publication_authorized': False}
    if type(raw) is not bytes:
        return Result(dict(evidence, status='REJECTED', reason='IMMUTABLE_BYTES_REQUIRED'))
    evidence.update(source_sha256=digest(raw), source_bytes=len(raw))
    try:
        if not raw or len(raw) > MAX_BYTES:
            fail('INPUT_BYTE_LIMIT')
        if role not in ('original', 'og'):
            fail('INVALID_ROLE')
        if not isinstance(extension, str) or extension.lower() not in EXTS:
            unsupported('UNSUPPORTED_EXTENSION')
        fmt = EXTS[extension.lower()]
        if role == 'og' and fmt not in ('JPEG', 'PNG'):
            unsupported('OG_REQUIRES_JPEG_OR_PNG')
        # Container validation first: no decoding of oversized/unknown structures.
        candidate, technical, removed = FILTERS[fmt](raw)
        source = probe(raw, extension, og=role == 'og')
        output, appearance, _ = verify_output(
            raw, candidate, extension, role, fmt, technical)
        evidence.update(status='SANITIZED_AND_VERIFIED', reason='BOUNDED_POLICY_VERIFIED',
                        format=fmt, removed_categories=sorted(set(removed)),
                        removed_blocks=len(removed), technical_sha256=technical,
                        appearance_sha256=appearance, source=source, output=output,
                        verification=['container_allowlist_reinspection',
                                      'independent_Pillow_all_frame_decode',
                                      'exact_compressed_and_technical_bytes'])
        return Result(evidence, candidate)
    except GateError as e:
        return Result(dict(evidence, status=e.status, reason=e.code))
    except Reject:
        return Result(dict(evidence, status='REJECTED', reason='IMAGE_VALIDATION_FAILED'))
    except Exception:
        # Never include exception text that could echo private metadata or paths.
        return Result(dict(evidence, status='REJECTED', reason='SANITIZER_OR_VERIFIER_FAILED'))
