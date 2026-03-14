package com.hariharan.zerokey.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.security.PasskeyManager
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class PasskeyManagerViewModel(
    private val passkeyManager: PasskeyManager
) : ViewModel() {

    // Placeholder for Passkey records since we don't have a DB for them yet
    private val _allPasskeys = MutableStateFlow<List<String>>(emptyList())
    val allPasskeys: StateFlow<List<String>> = _allPasskeys.asStateFlow()

    private val _actionResult = MutableSharedFlow<PasskeyAction>()
    val actionResult: SharedFlow<PasskeyAction> = _actionResult.asSharedFlow()

    fun deletePasskey(credentialId: String) {
        viewModelScope.launch {
            // Logic to delete from PasskeyManager
            _actionResult.emit(PasskeyAction.DeleteSuccess)
        }
    }
}

sealed class PasskeyAction {
    object DeleteSuccess : PasskeyAction()
    data class DeleteFailure(val reason: String) : PasskeyAction()
}
