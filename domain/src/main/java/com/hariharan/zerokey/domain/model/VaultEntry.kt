package com.hariharan.zerokey.domain.model

data class VaultEntry(
    val id: Int = 0,
    val serviceName: String,
    val username: String,
    val password: CharArray, // Use CharArray for better security
    val notes: String? = null,
    val isFavorite: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val lastModified: Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as VaultEntry
        if (id != other.id) return false
        return true
    }

    override fun hashCode(): Int {
        return id
    }
}
