package org.fosspass;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.Color;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Size;
import android.view.Gravity;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;

import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class QrScannerActivity extends AppCompatActivity {
    public static final String EXTRA_QR_VALUE = "org.fosspass.QR_VALUE";
    private static final int PERMISSION_REQUEST_CAMERA = 1001;
    private PreviewView previewView;
    private TextView scannerStatus;
    private ExecutorService cameraExecutor;
    private final MultiFormatReader qrReader = new MultiFormatReader();
    private final QrSyncSupport.AndroidQrFrameCollector frameCollector =
            new QrSyncSupport.AndroidQrFrameCollector();
    private boolean finished = false;
    private String lastStatus = "";
    private long lastStatusAtMs;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE);
        FrameLayout cameraLayout = new FrameLayout(this);
        previewView = new PreviewView(this);
        cameraLayout.addView(previewView, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        scannerStatus = new TextView(this);
        scannerStatus.setText("Point at the FossPass QR once and hold still");
        scannerStatus.setTextColor(Color.WHITE);
        scannerStatus.setBackgroundColor(0xB3000000);
        scannerStatus.setGravity(Gravity.CENTER);
        scannerStatus.setPadding(24, 16, 24, 16);
        FrameLayout.LayoutParams statusParams = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM);
        statusParams.setMargins(24, 24, 24, 48);
        cameraLayout.addView(scannerStatus, statusParams);
        setContentView(cameraLayout);
        cameraExecutor = Executors.newSingleThreadExecutor();
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startCamera();
        else ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.CAMERA}, PERMISSION_REQUEST_CAMERA);
    }

    private void startCamera() {
        ListenableFuture<ProcessCameraProvider> future = ProcessCameraProvider.getInstance(this);
        future.addListener(() -> {
            try { bindPreview(future.get()); }
            catch (ExecutionException | InterruptedException e) { Toast.makeText(this, "Camera start failed", Toast.LENGTH_SHORT).show(); finish(); }
        }, ContextCompat.getMainExecutor(this));
    }

    private void bindPreview(@NonNull ProcessCameraProvider provider) {
        Preview preview = new Preview.Builder().build();
        preview.setSurfaceProvider(previewView.getSurfaceProvider());
        CameraSelector selector = new CameraSelector.Builder().requireLensFacing(CameraSelector.LENS_FACING_BACK).build();
        ImageAnalysis analysis = new ImageAnalysis.Builder()
                .setTargetResolution(new Size(1280, 720))
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build();
        analysis.setAnalyzer(cameraExecutor, this::decodeImage);
        provider.unbindAll();
        provider.bindToLifecycle(this, selector, preview, analysis);
    }

    private void decodeImage(ImageProxy image) {
        try {
            if (finished || image.getFormat() != ImageFormat.YUV_420_888 || image.getPlanes().length < 1) return;
            ImageProxy.PlaneProxy yPlane = image.getPlanes()[0];
            ByteBuffer yBuffer = yPlane.getBuffer();
            byte[] paddedY = new byte[yBuffer.remaining()];
            yBuffer.get(paddedY);
            int width = image.getWidth();
            int height = image.getHeight();
            byte[] y = QrSyncSupport.compactYPlane(
                    paddedY, width, height, yPlane.getRowStride(), yPlane.getPixelStride());
            PlanarYUVLuminanceSource source = new PlanarYUVLuminanceSource(y, width, height, 0, 0, width, height, false);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
            Result result = qrReader.decodeWithState(bitmap);
            String raw = result.getText();
            if (raw != null && raw.trim().startsWith("{")) handleQr(raw);
        } catch (NotFoundException ignored) {
            // Normal: most frames do not contain a readable QR.
        } catch (Exception ignored) {
            // Keep scanning; malformed frames should not crash the scanner.
        } finally {
            qrReader.reset();
            image.close();
        }
    }

    private void handleQr(String raw) throws Exception {
        JSONObject object = new JSONObject(raw);
        switch (QrSyncSupport.classifyScannedQr(object)) {
            case ANDROID_BUNDLE:
                returnQr(raw);
                return;
            case DESKTOP_ONLY_FRAME:
                showScannerStatus("Desktop-only QR. On FossPass desktop choose Sync with Android.");
                return;
            case UNSUPPORTED_FOSSPASS:
                showScannerStatus("Unsupported FossPass QR. Scan an Android sync QR.");
                return;
            case UNRELATED:
                return;
            case ANDROID_FRAME:
                break;
        }
        int before = frameCollector.scannedCount();
        String complete = frameCollector.add(raw);
        if (complete != null) {
            returnQr(complete);
        } else if (frameCollector.scannedCount() > before) {
            int scanned = frameCollector.scannedCount();
            int expected = frameCollector.expectedCount();
            showScannerStatus("Scanning animated QR: " + scanned + " / " + expected);
        }
    }

    private void showScannerStatus(String message) {
        long now = SystemClock.elapsedRealtime();
        if (message.equals(lastStatus) && now - lastStatusAtMs < 2_000) return;
        lastStatus = message;
        lastStatusAtMs = now;
        runOnUiThread(() -> scannerStatus.setText(message));
    }

    private void returnQr(String value) {
        if (finished) return;
        finished = true;
        Intent out = new Intent();
        out.putExtra(EXTRA_QR_VALUE, value);
        setResult(RESULT_OK, out);
        finish();
    }

    @Override public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CAMERA && grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) startCamera();
        else { Toast.makeText(this, "Camera permission required for QR scan", Toast.LENGTH_SHORT).show(); finish(); }
    }

    @Override protected void onDestroy() {
        super.onDestroy();
        if (cameraExecutor != null) cameraExecutor.shutdown();
    }
}
