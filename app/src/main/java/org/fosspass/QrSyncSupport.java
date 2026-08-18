package org.fosspass;

import android.content.ComponentCallbacks2;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.DecodeHintType;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class QrSyncSupport {
    private QrSyncSupport() {}

    static Map<DecodeHintType, ?> qrDecodeHints() {
        EnumMap<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        hints.put(DecodeHintType.ALSO_INVERTED, Boolean.TRUE);
        hints.put(DecodeHintType.CHARACTER_SET, "UTF-8");
        return Collections.unmodifiableMap(hints);
    }

    static String scannerFeedback(int scanned, int expected) {
        if (expected > 0 && scanned >= expected) {
            return "QR collection complete — preparing encrypted import";
        }
        if (scanned > 0 && expected > 0) {
            return "QR detected — receiving encrypted vault: " + scanned + " / " + expected;
        }
        return "Camera active — looking for FossPass QR";
    }

    enum ScannedQrKind {
        ANDROID_FRAME,
        ANDROID_BUNDLE,
        DESKTOP_ONLY_FRAME,
        UNSUPPORTED_FOSSPASS,
        UNRELATED
    }

    static ScannedQrKind classifyScannedQr(JSONObject object) {
        String type = object.optString("type");
        if ("fosspass-android-qr-frame-v1".equals(type)) return ScannedQrKind.ANDROID_FRAME;
        if ("fosspass-qr-sync-v1".equals(type) || "fosspass-vault-file-v1".equals(type)) {
            return ScannedQrKind.ANDROID_BUNDLE;
        }
        if ("fosspass-qr-frame".equals(type)) return ScannedQrKind.DESKTOP_ONLY_FRAME;
        if (type.startsWith("fosspass-")) return ScannedQrKind.UNSUPPORTED_FOSSPASS;
        return ScannedQrKind.UNRELATED;
    }

    static boolean isStagedAndroidBundle(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > PasswordImportReader.MAX_IMPORT_BYTES) return false;
        try {
            JSONObject bundle = new JSONObject(raw);
            if (classifyScannedQr(bundle) != ScannedQrKind.ANDROID_BUNDLE) return false;
            String salt = bundle.optString("salt", "");
            String iv = bundle.optString("iv", "");
            String ciphertext = bundle.optString("ciphertext", "");
            if (!salt.matches("[A-Za-z0-9+/]{22}==")
                    || !iv.matches("[A-Za-z0-9+/]{16}")
                    || ciphertext.isEmpty()
                    || !ciphertext.matches("[A-Za-z0-9+/]+={0,2}")) return false;
            if (!bundle.has("version")) return !bundle.has("compression");
            int version = bundle.optInt("version", -1);
            if (version == 2) return !bundle.has("compression");
            return version == 3 && "zlib".equals(bundle.optString("compression"));
        } catch (Exception ignored) {
            return false;
        }
    }

    static String requireCompleteAndroidBundle(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            throw new IllegalArgumentException("No encrypted Android bundle was supplied");
        }
        String trimmed = raw.trim();
        try {
            JSONObject object = new JSONObject(trimmed);
            ScannedQrKind kind = classifyScannedQr(object);
            if (kind == ScannedQrKind.ANDROID_FRAME) {
                throw new IllegalArgumentException(
                        "This is only one animated frame. Use Scan QR and keep the camera pointed until collection finishes.");
            }
            if (kind == ScannedQrKind.DESKTOP_ONLY_FRAME) {
                throw new IllegalArgumentException(
                        "This is a desktop-only vault-key QR. On desktop choose Sync with Android.");
            }
            if (kind != ScannedQrKind.ANDROID_BUNDLE || !isStagedAndroidBundle(trimmed)) {
                throw new IllegalArgumentException("Unsupported or incomplete Android sync bundle");
            }
            return trimmed;
        } catch (IllegalArgumentException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalArgumentException("Android sync data is not valid JSON", error);
        }
    }

    static int nextFrameIndex(int currentIndex, int frameCount) {
        if (frameCount < 1) return 0;
        return (Math.max(0, currentIndex) + 1) % frameCount;
    }

    static boolean shouldLockForTrimMemory(boolean externalFlowInProgress, int level) {
        return !externalFlowInProgress && level >= ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN;
    }

    static byte[] compactYPlane(byte[] source, int width, int height, int rowStride, int pixelStride) {
        if (width <= 0 || height <= 0 || rowStride <= 0 || pixelStride <= 0) {
            throw new IllegalArgumentException("Invalid Y-plane dimensions");
        }
        long lastIndex = (long) (height - 1) * rowStride + (long) (width - 1) * pixelStride;
        if (lastIndex >= source.length) {
            throw new IllegalArgumentException("Y-plane buffer is smaller than its declared layout");
        }
        byte[] compact = new byte[width * height];
        int target = 0;
        for (int y = 0; y < height; y++) {
            int rowStart = y * rowStride;
            for (int x = 0; x < width; x++) {
                compact[target++] = source[rowStart + x * pixelStride];
            }
        }
        return compact;
    }

    static String sha256Hex(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder(digest.length * 2);
        for (byte item : digest) out.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        return out.toString();
    }

    static List<String> splitAndroidBundle(String bundle, int chunkSize, String bundleId)
            throws Exception {
        if (bundle == null || bundle.isEmpty() || bundle.length() > PasswordImportReader.MAX_IMPORT_BYTES) {
            throw new IllegalArgumentException("Android QR bundle is empty or exceeds 20 MiB");
        }
        if (chunkSize < 128 || chunkSize > 1_200 || bundleId == null || bundleId.isEmpty()) {
            throw new IllegalArgumentException("Invalid Android QR frame settings");
        }
        int frameCount = (bundle.length() + chunkSize - 1) / chunkSize;
        if (frameCount > 30_000) throw new IllegalArgumentException("Android QR bundle has too many frames");
        String digest = sha256Hex(bundle);
        List<String> frames = new ArrayList<>(frameCount);
        for (int index = 0; index < frameCount; index++) {
            int start = index * chunkSize;
            JSONObject frame = new JSONObject();
            frame.put("type", "fosspass-android-qr-frame-v1");
            frame.put("version", 1);
            frame.put("bundle_id", bundleId);
            frame.put("frame_index", index);
            frame.put("frame_count", frameCount);
            frame.put("payload", bundle.substring(start, Math.min(start + chunkSize, bundle.length())));
            frame.put("bundle_sha256", digest);
            frames.add(frame.toString());
        }
        return frames;
    }

    static final class AndroidQrFrameCollector {
        private static final int MAX_FRAME_COUNT = 30_000;
        private static final int MAX_PAYLOAD_CHARS = 1_200;
        private static final int MAX_BUNDLE_CHARS = PasswordImportReader.MAX_IMPORT_BYTES;

        private final Map<Integer, String> payloads = new HashMap<>();
        private String bundleId;
        private String digest;
        private int frameCount;
        private int totalChars;

        String add(String rawFrame) throws Exception {
            JSONObject frame = new JSONObject(rawFrame);
            if (!"fosspass-android-qr-frame-v1".equals(frame.optString("type"))
                    || frame.optInt("version", -1) != 1) {
                throw new IllegalArgumentException("Unsupported Android QR frame");
            }
            String incomingId = frame.getString("bundle_id");
            String incomingDigest = frame.getString("bundle_sha256");
            int incomingCount = frame.getInt("frame_count");
            int index = frame.getInt("frame_index");
            String payload = frame.getString("payload");
            if (incomingId.isEmpty() || !incomingDigest.matches("[0-9a-f]{64}")
                    || incomingCount < 1 || incomingCount > MAX_FRAME_COUNT
                    || index < 0 || index >= incomingCount
                    || payload.length() > MAX_PAYLOAD_CHARS) {
                throw new IllegalArgumentException("Invalid Android QR frame metadata");
            }
            if (bundleId == null) {
                bundleId = incomingId;
                digest = incomingDigest;
                frameCount = incomingCount;
            } else if (!bundleId.equals(incomingId) || !digest.equals(incomingDigest)
                    || frameCount != incomingCount) {
                throw new IllegalArgumentException("QR frame belongs to a different bundle");
            }
            if (!payloads.containsKey(index)) {
                if ((long) totalChars + payload.length() > MAX_BUNDLE_CHARS) {
                    throw new IllegalArgumentException("QR bundle exceeds 20 MiB");
                }
                payloads.put(index, payload);
                totalChars += payload.length();
            } else if (!payloads.get(index).equals(payload)) {
                throw new IllegalArgumentException("Conflicting duplicate QR frame");
            }
            if (payloads.size() != frameCount) return null;

            StringBuilder bundle = new StringBuilder(totalChars);
            for (int i = 0; i < frameCount; i++) {
                String part = payloads.get(i);
                if (part == null) return null;
                bundle.append(part);
            }
            String complete = bundle.toString();
            if (!MessageDigest.isEqual(
                    digest.getBytes(StandardCharsets.US_ASCII),
                    sha256Hex(complete).getBytes(StandardCharsets.US_ASCII))) {
                throw new SecurityException("Android QR bundle integrity check failed");
            }
            return complete;
        }

        int scannedCount() {
            return payloads.size();
        }

        int expectedCount() {
            return frameCount;
        }
    }
}
