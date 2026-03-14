package com.hariharan.zerokey.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.securityanalytics.SecurityScoreCalculator
import com.hariharan.zerokey.securityanalytics.VaultSecurityAnalyzer
import com.hariharan.zerokey.ui.state.SecurityDashboardUiState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class SecurityDashboardViewModel(
    private val repository: PasswordRepository,
    private val vaultSecurityAnalyzer: VaultSecurityAnalyzer,
    private val scoreCalculator: SecurityScoreCalculator
) : ViewModel() {

    private val _uiState = MutableStateFlow(SecurityDashboardUiState())
    val uiState: StateFlow<SecurityDashboardUiState> = _uiState.asStateFlow()

    fun loadReport(hmacKey: ByteArray) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            try {
                val credentials = repository.getPasswords()
                val breachedIds = emptySet<Int>() 

                val report = vaultSecurityAnalyzer.buildReport(
                    credentials = credentials,
                    hmacKey = hmacKey,
                    breachedIds = breachedIds
                )

                _uiState.update { 
                    it.copy(
                        isLoading = false,
                        securityScore = report.securityScore,
                        weakPasswordCount = report.weakPasswords.size,
                        duplicatePasswordCount = report.duplicateGroups.size,
                        breachedPasswordCount = report.breachedCredentials.size,
                        recommendations = report.weakPasswords.map { pw -> "Strengthen password for ${pw.domain}" }
                    )
                }
            } catch (e: Exception) {
                _uiState.update { 
                    it.copy(
                        isLoading = false, 
                        errorMessage = e.message ?: "Failed to load report"
                    )
                }
            }
        }
    }
}
