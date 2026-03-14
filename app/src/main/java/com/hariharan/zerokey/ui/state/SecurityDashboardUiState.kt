package com.hariharan.zerokey.ui.state

/**
 * UI State for the Security Dashboard.
 * Encapsulates all data required to render the security analysis overview.
 */
data class SecurityDashboardUiState(
    val isLoading: Boolean = true,
    val securityScore: Int = 0,
    val weakPasswordCount: Int = 0,
    val duplicatePasswordCount: Int = 0,
    val breachedPasswordCount: Int = 0,
    val recommendations: List<String> = emptyList(),
    val errorMessage: String? = null
)
