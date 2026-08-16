package org.fosspass;

import android.content.ComponentCallbacks2;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class QrSyncSupport {
    private QrSyncSupport() {}

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
