package org.fosspass;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.json.JSONObject;
import org.junit.Test;

public class QrSyncRegressionTest {
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

    private static String frame(String id, int index, int count, String payload, String digest) {
        return "{\"type\":\"fosspass-android-qr-frame-v1\",\"version\":1,"
                + "\"bundle_id\":\"" + id + "\",\"frame_index\":" + index
                + ",\"frame_count\":" + count + ",\"payload\":\"" + payload.replace("\"", "\\\"")
                + "\",\"bundle_sha256\":\"" + digest + "\"}";
    }
}
