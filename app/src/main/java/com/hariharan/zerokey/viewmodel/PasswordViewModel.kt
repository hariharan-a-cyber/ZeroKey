package com.hariharan.zerokey.viewmodel

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.utils.PasswordStrength
import com.hariharan.zerokey.utils.PasswordUtils
import kotlinx.coroutines.launch

class PasswordViewModel(
    private val repository: PasswordRepository
) : ViewModel() {

    private var allPasswords = listOf<PasswordItem>()
    
    var passwords = mutableStateListOf<PasswordItem>()
        private set

    var searchQuery by mutableStateOf("")
        private set

    init {
        loadPasswords()
    }

    fun loadPasswords() {
        viewModelScope.launch {
            allPasswords = repository.getPasswords()
            filterPasswords()
        }
    }

    fun onSearchQueryChange(query: String) {
        searchQuery = query
        filterPasswords()
    }

    private fun filterPasswords() {
        passwords.clear()
        if (searchQuery.isBlank()) {
            passwords.addAll(allPasswords)
        } else {
            val filtered = allPasswords.filter {
                it.serviceName.contains(searchQuery, ignoreCase = true) ||
                it.username.contains(searchQuery, ignoreCase = true)
            }
            passwords.addAll(filtered)
        }
    }

    fun addPassword(service: String, username: String, password: String, notes: String? = null) {
        viewModelScope.launch {
            repository.savePassword(service, username, password, notes)
            loadPasswords()
        }
    }

    fun deletePassword(item: PasswordItem) {
        viewModelScope.launch {
            repository.deletePassword(item.id)
            loadPasswords()
        }
    }

    /**
     * Checks if a password is a duplicate across other accounts.
     */
    fun isDuplicatePassword(password: String): Boolean {
        return allPasswords.any { it.password == password }
    }

    /**
     * Calculates the strength of a given password string.
     */
    fun getPasswordStrength(password: String): PasswordStrength {
        return PasswordUtils.calculateStrength(password)
    }
}
