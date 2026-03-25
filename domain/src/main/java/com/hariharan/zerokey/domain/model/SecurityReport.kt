package com.hariharan.zerokey.domain.model

data class SecurityReport(
    val score: Int,
    val weakPasswordCount: Int,
    val duplicatePasswordCount: Int,
    val compromisedPasswordCount: Int,
    val recommendations: List<String>
)
