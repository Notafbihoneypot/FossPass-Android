package org.fosspass;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.Dataset;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;
import android.view.View;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;

import java.util.List;

import uniffi.fosspass_core.PublicEntry;

public final class FossPassAutofillService extends AutofillService {
    static final String EXTRA_ENTRY_ID = "org.fosspass.autofill.ENTRY_ID";
    static final String EXTRA_USERNAME_ID = "org.fosspass.autofill.USERNAME_ID";
    static final String EXTRA_PASSWORD_ID = "org.fosspass.autofill.PASSWORD_ID";

    @Override public void onFillRequest(FillRequest request, CancellationSignal cancellation,
                                        FillCallback callback) {
        List<PublicEntry> entries = VaultSession.entries();
        if (entries.isEmpty() || cancellation.isCanceled()) {
            callback.onSuccess(null);
            return;
        }
        List<FillContext> contexts = request.getFillContexts();
        if (contexts.isEmpty()) {
            callback.onSuccess(null);
            return;
        }
        Fields fields = new Fields();
        AssistStructure structure = contexts.get(contexts.size() - 1).getStructure();
        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            scan(structure.getWindowNodeAt(i).getRootViewNode(), fields);
        }
        if (fields.username == null && fields.password == null) {
            callback.onSuccess(null);
            return;
        }

        FillResponse.Builder response = new FillResponse.Builder();
        for (PublicEntry entry : entries) {
            RemoteViews label = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
            label.setTextViewText(android.R.id.text1, entry.getTitle());
            Intent auth = new Intent(this, AutofillAuthActivity.class)
                    .putExtra(EXTRA_ENTRY_ID, entry.getEntryId())
                    .putExtra(EXTRA_USERNAME_ID, fields.username)
                    .putExtra(EXTRA_PASSWORD_ID, fields.password);
            int requestCode = entry.getEntryId().hashCode();
            PendingIntent pending = PendingIntent.getActivity(this, requestCode, auth,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Dataset.Builder dataset = new Dataset.Builder(label).setAuthentication(pending.getIntentSender());
            if (fields.username != null) dataset.setValue(fields.username, (AutofillValue) null);
            if (fields.password != null) dataset.setValue(fields.password, (AutofillValue) null);
            response.addDataset(dataset.build());
        }
        callback.onSuccess(response.build());
    }

    @Override public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        callback.onSuccess();
    }

    private static void scan(AssistStructure.ViewNode node, Fields fields) {
        if (node == null) return;
        if (node.getAutofillId() != null && node.getAutofillType() == View.AUTOFILL_TYPE_TEXT) {
            AutofillFieldClassifier.Kind kind = AutofillFieldClassifier.classify(
                    node.getAutofillHints(), node.getInputType());
            if (kind == AutofillFieldClassifier.Kind.USERNAME && fields.username == null) {
                fields.username = node.getAutofillId();
            } else if (kind == AutofillFieldClassifier.Kind.PASSWORD && fields.password == null) {
                fields.password = node.getAutofillId();
            }
        }
        for (int i = 0; i < node.getChildCount(); i++) scan(node.getChildAt(i), fields);
    }

    private static final class Fields {
        AutofillId username;
        AutofillId password;
    }
}
