package com.hariharan.zerokey.viewmodel

import com.hariharan.zerokey.securityanalytics.SecurityGrade
import com.hariharan.zerokey.securityanalytics.VaultSecurityReport

sealed class SecurityDashboardUiState {
    object Loading : SecurityDashboardUiState()
    data class Ready(
        val score: Int,
        val grade: SecurityGrade,
        val report: VaultSecurityReport
    ) : SecurityDashboardUiState()
    data class Error(val message: String) : SecurityDashboardUiState()
}
