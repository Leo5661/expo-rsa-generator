package com.phonehint

import android.app.Activity
import android.content.Intent
import com.facebook.react.bridge.*
import com.google.android.gms.auth.api.phone.PhoneNumberHint
import com.google.android.gms.auth.api.phone.PhoneAuthProvider
import com.google.android.gms.common.api.ApiException

class PhoneHintModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext), ActivityEventListener {

    private var hintPromise: Promise? = null

    init {
        reactContext.addActivityEventListener(this)
    }

    override fun getName(): String {
        return "PhoneHintModule"
    }

    @ReactMethod
    fun getPhoneHint(promise: Promise) {
        hintPromise = promise
        try {
            val hintRequest = PhoneAuthProvider.getClient(reactApplicationContext).hintPickerIntent
            currentActivity?.startActivityForResult(hintRequest, PHONE_HINT_REQUEST)
        } catch (e: Exception) {
            hintPromise?.reject("PHONE_HINT_ERROR", e.message)
            hintPromise = null
        }
    }

    override fun onActivityResult(activity: Activity?, requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == PHONE_HINT_REQUEST) {
            if (resultCode == Activity.RESULT_OK) {
                val hint = data?.getParcelableExtra<PhoneNumberHint>(PhoneNumberHint.EXTRA_HINT)
                val phoneNumber = hint?.phoneNumber.toString()
                hintPromise?.resolve(phoneNumber)
            } else {
                hintPromise?.reject("PHONE_HINT_ERROR", "Phone hint request failed")
            }
            hintPromise = null
        }
    }

    override fun onNewIntent(intent: Intent?) {}

    companion object {
        private const val PHONE_HINT_REQUEST = 1001
    }
}