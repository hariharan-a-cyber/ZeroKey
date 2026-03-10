package com.hariharan.zerokey.security

/**
 * Required Data Class for ZeroKey security.
 */
data class EncryptedData(
    val cipherText: ByteArray,
    val iv: ByteArray
)
