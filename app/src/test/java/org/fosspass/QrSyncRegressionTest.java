package org.fosspass;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import org.json.JSONObject;
import org.junit.Test;

public class QrSyncRegressionTest {
    @Test
    public void scannerUsesQrOnlyTryHarderAndInvertedDecodeHints() {
        Map<DecodeHintType, ?> hints = QrSyncSupport.qrDecodeHints();
        assertEquals(Boolean.TRUE, hints.get(DecodeHintType.TRY_HARDER));
        assertEquals(Boolean.TRUE, hints.get(DecodeHintType.ALSO_INVERTED));
        assertTrue(((Collection<?>) hints.get(DecodeHintType.POSSIBLE_FORMATS))
                .contains(BarcodeFormat.QR_CODE));
    }

    @Test
    public void cameraReadableFrameRoundTripsThroughTheAndroidDecoder() throws Exception {
        String bundle = "{\"type\":\"fosspass-qr-sync-v1\",\"ciphertext\":\""
                + "x".repeat(2_000) + "\"}";
        String frame = QrSyncSupport.splitAndroidBundle(bundle, 600, "camera-test").get(0);
        Map<EncodeHintType, Object> encodeHints = new HashMap<>();
        encodeHints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        encodeHints.put(EncodeHintType.MARGIN, 2);
        BitMatrix matrix = new QRCodeWriter().encode(
                frame, BarcodeFormat.QR_CODE, 640, 640, encodeHints);
        int[] pixels = new int[640 * 640];
        for (int y = 0; y < 640; y++) {
            for (int x = 0; x < 640; x++) {
                pixels[y * 640 + x] = matrix.get(x, y) ? 0xff000000 : 0xffffffff;
            }
        }
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(
                new RGBLuminanceSource(640, 640, pixels)));
        MultiFormatReader reader = new MultiFormatReader();
        reader.setHints(QrSyncSupport.qrDecodeHints());
        Result decoded = reader.decodeWithState(bitmap);
        assertEquals(frame, decoded.getText());
    }

    @Test
    public void scannerFeedbackDistinguishesLookingDetectedAndComplete() {
        assertTrue(QrSyncSupport.scannerFeedback(0, 0).contains("Camera active"));
        assertTrue(QrSyncSupport.scannerFeedback(2, 5).contains("2 / 5"));
        assertTrue(QrSyncSupport.scannerFeedback(5, 5).contains("complete"));
    }

    @Test
    public void externalScannerFlowDoesNotLockVaultWhenUiIsHidden() {
        assertFalse(QrSyncSupport.shouldLockForTrimMemory(true, android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN));
        assertTrue(QrSyncSupport.shouldLockForTrimMemory(false, android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN));
    }

    @Test
    public void compactYPlaneRemovesPixelCameraRowPadding() {
        byte[] padded = new byte[] {
                1, 2, 3, 99, 99,
                4, 5, 6, 99, 99
        };

        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6},
                QrSyncSupport.compactYPlane(padded, 3, 2, 5, 1));
    }

    @Test
    public void compactYPlaneHandlesPixelStride() {
        byte[] interleaved = new byte[] {
                1, 90, 2, 90, 3, 90,
                4, 90, 5, 90, 6, 90
        };

        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6},
                QrSyncSupport.compactYPlane(interleaved, 3, 2, 6, 2));
    }

    @Test
    public void androidQrCollectorReassemblesOutOfOrderFramesAndIgnoresDuplicates() throws Exception {
        String bundle = "{\"type\":\"fosspass-qr-sync-v1\",\"ciphertext\":\"abcdef\"}";
        String digest = QrSyncSupport.sha256Hex(bundle);
        String first = frame("bundle-1", 0, 2, bundle.substring(0, 24), digest);
        String second = frame("bundle-1", 1, 2, bundle.substring(24), digest);
        QrSyncSupport.AndroidQrFrameCollector collector = new QrSyncSupport.AndroidQrFrameCollector();

        assertNull(collector.add(second));
        assertNull(collector.add(second));
        assertEquals(1, collector.scannedCount());
        assertEquals(bundle, collector.add(first));
        assertEquals(2, collector.expectedCount());
    }

    @Test
    public void androidQrCollectorRejectsTamperingAndMixedBundles() throws Exception {
        String bundle = "{\"type\":\"fosspass-qr-sync-v1\",\"ciphertext\":\"abcdef\"}";
        String digest = QrSyncSupport.sha256Hex(bundle);
        QrSyncSupport.AndroidQrFrameCollector collector = new QrSyncSupport.AndroidQrFrameCollector();
        assertNull(collector.add(frame("bundle-1", 0, 2, bundle.substring(0, 24), digest)));
        assertThrows(IllegalArgumentException.class,
                () -> collector.add(frame("bundle-2", 1, 2, bundle.substring(24), digest)));

        QrSyncSupport.AndroidQrFrameCollector tampered = new QrSyncSupport.AndroidQrFrameCollector();
        assertNull(tampered.add(frame("bundle-1", 0, 2, bundle.substring(0, 24), digest)));
        assertThrows(SecurityException.class,
                () -> tampered.add(frame("bundle-1", 1, 2, bundle.substring(24) + "A", digest)));
    }

    @Test
    public void androidQrExporterSplitsLargeBundlesIntoScannerCompatibleFrames() throws Exception {
        String bundle = "{\"type\":\"fosspass-qr-sync-v1\",\"ciphertext\":\"" + "x".repeat(8_000) + "\"}";
        List<String> frames = QrSyncSupport.splitAndroidBundle(bundle, 700, "bundle-export");
        assertTrue(frames.size() > 1);
        for (int index = 0; index < frames.size(); index++) {
            JSONObject frame = new JSONObject(frames.get(index));
            assertEquals("fosspass-android-qr-frame-v1", frame.getString("type"));
            assertEquals(index, frame.getInt("frame_index"));
            assertEquals(frames.size(), frame.getInt("frame_count"));
            assertTrue(frames.get(index).length() < 1_100);
        }
        QrSyncSupport.AndroidQrFrameCollector collector = new QrSyncSupport.AndroidQrFrameCollector();
        String complete = null;
        for (int index = frames.size() - 1; index >= 0; index--) complete = collector.add(frames.get(index));
        assertEquals(bundle, complete);
    }

    @Test
    public void androidQrCollectorAcceptsDesktopChunkSize1000() throws Exception {
        String bundle = "{\"type\":\"fosspass-qr-sync-v1\",\"ciphertext\":\""
                + "x".repeat(7_500) + "\"}";
        List<String> frames = QrSyncSupport.splitAndroidBundle(bundle, 1_000, "desktop-1000");
        QrSyncSupport.AndroidQrFrameCollector collector =
                new QrSyncSupport.AndroidQrFrameCollector();
        String complete = null;
        for (int index = 1; index < frames.size(); index += 2) complete = collector.add(frames.get(index));
        for (int index = 0; index < frames.size(); index += 2) complete = collector.add(frames.get(index));
        assertEquals(bundle, complete);
    }

    @Test
    public void scannerClassificationRejectsDesktopOnlyAndUnrelatedFossPassFrames() throws Exception {
        assertEquals(QrSyncSupport.ScannedQrKind.DESKTOP_ONLY_FRAME,
                QrSyncSupport.classifyScannedQr(new JSONObject("{\"type\":\"fosspass-qr-frame\"}")));
        assertEquals(QrSyncSupport.ScannedQrKind.UNSUPPORTED_FOSSPASS,
                QrSyncSupport.classifyScannedQr(new JSONObject("{\"type\":\"fosspass-other-v9\"}")));
        assertEquals(QrSyncSupport.ScannedQrKind.ANDROID_FRAME,
                QrSyncSupport.classifyScannedQr(new JSONObject("{\"type\":\"fosspass-android-qr-frame-v1\"}")));
        assertEquals(QrSyncSupport.ScannedQrKind.ANDROID_BUNDLE,
                QrSyncSupport.classifyScannedQr(new JSONObject("{\"type\":\"fosspass-qr-sync-v1\"}")));
        assertEquals(QrSyncSupport.ScannedQrKind.UNRELATED,
                QrSyncSupport.classifyScannedQr(new JSONObject("{\"type\":\"some-other-qr\"}")));
    }

    @Test
    public void stagedQrImportAcceptsOnlyCompleteAndroidEncryptedBundles() {
        String valid = "{\"type\":\"fosspass-qr-sync-v1\",\"version\":3,\"compression\":\"zlib\","
                + "\"salt\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"iv\":\"AAAAAAAAAAAAAAAA\","
                + "\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}";
        assertTrue(QrSyncSupport.isStagedAndroidBundle(valid));
        assertFalse(QrSyncSupport.isStagedAndroidBundle("{\"type\":\"fosspass-qr-frame\"}"));
        assertFalse(QrSyncSupport.isStagedAndroidBundle("{\"type\":\"fosspass-qr-sync-v1\",\"ciphertext\":\"AAAA\"}"));
        assertFalse(QrSyncSupport.isStagedAndroidBundle("not-json"));
    }

    @Test
    public void importValidationReturnsCompleteBundleAndRejectsIndividualFramesBeforeRust() throws Exception {
        String valid = "{\"type\":\"fosspass-qr-sync-v1\",\"version\":3,\"compression\":\"zlib\","
                + "\"salt\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"iv\":\"AAAAAAAAAAAAAAAA\","
                + "\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}";
        assertEquals(valid, QrSyncSupport.requireCompleteAndroidBundle("  " + valid + "  "));

        IllegalArgumentException frameError = assertThrows(IllegalArgumentException.class,
                () -> QrSyncSupport.requireCompleteAndroidBundle(
                        "{\"type\":\"fosspass-android-qr-frame-v1\",\"frame_index\":0}"));
        assertTrue(frameError.getMessage().contains("Scan QR"));
        IllegalArgumentException desktopError = assertThrows(IllegalArgumentException.class,
                () -> QrSyncSupport.requireCompleteAndroidBundle(
                        "{\"type\":\"fosspass-qr-frame\"}"));
        assertTrue(desktopError.getMessage().contains("desktop-only"));
    }

    @Test
    public void animatedQrNavigationLoopsWithoutManualNextPresses() {
        assertEquals(1, QrSyncSupport.nextFrameIndex(0, 4));
        assertEquals(0, QrSyncSupport.nextFrameIndex(3, 4));
        assertEquals(0, QrSyncSupport.nextFrameIndex(0, 0));
    }

    private static String frame(String id, int index, int count, String payload, String digest) {
        return "{\"type\":\"fosspass-android-qr-frame-v1\",\"version\":1,"
                + "\"bundle_id\":\"" + id + "\",\"frame_index\":" + index
                + ",\"frame_count\":" + count + ",\"payload\":\"" + payload.replace("\"", "\\\"")
                + "\",\"bundle_sha256\":\"" + digest + "\"}";
    }
}
