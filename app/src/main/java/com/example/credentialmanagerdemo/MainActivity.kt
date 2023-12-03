package com.example.credentialmanagerdemo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialCustomException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.lifecycle.lifecycleScope
import com.example.credentialmanagerdemo.databinding.ActivityMainBinding
import kotlinx.coroutines.launch
import java.lang.Exception
import java.security.SecureRandom

class MainActivity : AppCompatActivity() {
    private lateinit var binding:ActivityMainBinding
    private lateinit var credentialManager: CredentialManager
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        credentialManager = CredentialManager.create(this)

        binding.signUp.setOnClickListener {
            lifecycleScope.launch {
                val key = createPassKey()
                key?.let {
                    DataProvider.setSignedInThroughPasskeys(true)
                }
            }
        }

    }

    private suspend fun createPassKey() : CreatePublicKeyCredentialResponse? {
        //first we need to fitch data from server.
        val createPublicKeyCredentialRequest = CreatePublicKeyCredentialRequest(
            requestJson = fetchRegistrationJsonFromServer(),
            origin = null
            )
        var result : CreatePublicKeyCredentialResponse? = null
        try {
            result = credentialManager.createCredential(
                context = this,
                request = createPublicKeyCredentialRequest
            )  as CreatePublicKeyCredentialResponse

        }catch (e: CreateCredentialException){
            //handle failure
            handlePasskeyFailure(e)
        }

        return result
    }

    private fun fetchRegistrationJsonFromServer():String{
        val response = this.readFromAsset("RegFromServer")
        return response.replace("<userId>", getEncodedUserId())
            .replace("<userName>", binding.userName.text.toString())
            .replace("<userDisplayName>", binding.userName.text.toString())
            .replace("<challenge>", getEncodedChallenge())
    }

    private fun getEncodedChallenge(): String {
        val random = SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.encodeToString(
            bytes,
            Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING
        )
    }

    private fun getEncodedUserId(): String {
        val random = SecureRandom()
        val bytes = ByteArray(64)
        random.nextBytes(bytes)
        return Base64.encodeToString(
            bytes,
            Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING
        )
    }

    // These are types of errors that can occur during passkey creation.
    private fun handlePasskeyFailure(e: CreateCredentialException) {
        val msg = when (e) {
            is CreatePublicKeyCredentialDomException -> {
                // Handle the passkey DOM errors thrown according to the
                // WebAuthn spec using e.domError
                "An error occurred while creating a passkey, please check logs for additional details."
            }
            is CreateCredentialCancellationException -> {
                // The user intentionally canceled the operation and chose not
                // to register the credential.
                "The user intentionally canceled the operation and chose not to register the credential. Check logs for additional details."
            }
            is CreateCredentialInterruptedException -> {
                // Retry-able error. Consider retrying the call.
                "The operation was interrupted, please retry the call. Check logs for additional details."
            }
            is CreateCredentialProviderConfigurationException -> {
                // Your app is missing the provider configuration dependency.
                // Most likely, you're missing "credentials-play-services-auth".
                "Your app is missing the provider configuration dependency. Check logs for additional details."
            }
            is CreateCredentialUnknownException -> {
                "An unknown error occurred while creating passkey. Check logs for additional details."
            }
            is CreateCredentialCustomException -> {
                // You have encountered an error from a 3rd-party SDK. If you
                // make the API call with a request object that's a subclass of
                // CreateCustomCredentialRequest using a 3rd-party SDK, then you
                // should check for any custom exception type constants within
                // that SDK to match with e.type. Otherwise, drop or log the
                // exception.
                "An unknown error occurred from a 3rd party SDK. Check logs for additional details."
            }
            else -> {
                Log.w("Auth", "Unexpected exception type ${e::class.java.name}")
                "An unknown error occurred."
            }
        }
        Log.e("Auth", "createPasskey failed with exception: " + e.message.toString())
        showErrorAlert(msg)
    }
}