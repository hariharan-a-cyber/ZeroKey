package com.hariharan.zerokey.data.repository

/**
 * A plain-text representation of a password entry for use in the UI layer.
 */
data class PasswordItem(
    val id: Int,
    val serviceName: String,
    val username: String,
    val password: String,
    val notes: String?
)
