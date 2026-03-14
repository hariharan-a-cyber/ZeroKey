package com.hariharan.zerokey.data.database

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "audit_logs")
data class AuditLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val eventType: String,
    val details: String,
    val timestamp: Long = System.currentTimeMillis()
)
