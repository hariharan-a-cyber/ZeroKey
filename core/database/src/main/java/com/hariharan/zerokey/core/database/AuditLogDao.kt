package com.hariharan.zerokey.core.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface AuditLogDao {
    @Insert
    suspend fun insertLog(log: AuditLogEntity)

    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    suspend fun getAllLogs(): List<AuditLogEntity>

    @Query("DELETE FROM audit_logs")
    suspend fun clearLogs()
}
