package com.hariharan.zerokey.data.database

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Production-Grade Secure Database Model.
 * All sensitive metadata is now encrypted with its own unique IV.
 */
@Entity(tableName = "passwords")
data class PasswordEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,

    val encryptedServiceName: String,
    val serviceNameIv: String,

    val encryptedUsername: String,
    val usernameIv: String,

    val encryptedPassword: String,
    val passwordIv: String,

    val encryptedNotes: String? = null,
    val notesIv: String? = null,

    val isFavorite: Boolean = false,
    val createdAt: Long = System.currentTimeMillis()
)
