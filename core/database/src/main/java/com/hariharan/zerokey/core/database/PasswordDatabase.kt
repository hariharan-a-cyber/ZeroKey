package com.hariharan.zerokey.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        PasswordEntity::class, 
        PasskeyEntity::class, 
        SecurityEventEntity::class, 
        SharedCredentialEntity::class, 
        EmergencyAccessEntity::class, 
        SyncMetadataEntity::class, 
        SecurityScoreHistoryEntity::class
    ],
    version = 4,
    exportSchema = false
)
abstract class PasswordDatabase : RoomDatabase() {

    abstract fun passwordDao(): PasswordDao

    companion object {
        @Volatile
        private var INSTANCE: PasswordDatabase? = null

        fun getDatabase(context: Context): PasswordDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PasswordDatabase::class.java,
                    "ZeroKey_Vault_DB"
                )
                .fallbackToDestructiveMigration()
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
