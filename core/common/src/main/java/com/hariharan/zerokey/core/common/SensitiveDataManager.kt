package com.hariharan.zerokey.core.common

import java.util.Arrays

/**
 * Utility for handling sensitive data in memory.
 */
object SensitiveDataManager {

    /**
     * Overwrites the memory of a CharArray with zeros.
     */
    fun clearSensitiveData(data: CharArray?) {
        data?.let {
            Arrays.fill(it, '\u0000')
        }
    }

    /**
     * Overwrites the memory of a ByteArray with zeros.
     */
    fun clearSensitiveData(data: ByteArray?) {
        data?.let {
            Arrays.fill(it, 0.toByte())
        }
    }
}
