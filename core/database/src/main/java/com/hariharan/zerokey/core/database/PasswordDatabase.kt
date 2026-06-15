package com.hariharan.zerokey.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration

@Database(
    entities = [
        PasswordEntity::class, 
        VaultMetadata::class, 
        AuditLogEntity::class,
        PasskeyEntity::class,
        SecurityEventEntity::class,
        SharedCredentialEntity::class,
        EmergencyAccessEntity::class,
        SyncMetadataEntity::class,
        SecurityScoreHistoryEntity::class
    ],
    version = 6,
    exportSchema = false
)
abstract class PasswordDatabase : RoomDatabase() {

    abstract fun passwordDao(): PasswordDao
    abstract fun vaultMetadataDao(): VaultMetadataDao
    abstract fun auditLogDao(): AuditLogDao

    companion object {
        // Add a Migration(from, to) object here for EVERY future schema/version change.
        // Never delete user data. Example:
        // private val MIGRATION_6_7 = object : Migration(6, 7) {
        //     override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
        //         db.execSQL("ALTER TABLE passwords ADD COLUMN newField TEXT")
        //     }
        // }
        private val MIGRATIONS: Array<Migration> = arrayOf()

        @Volatile
        private var INSTANCE: PasswordDatabase? = null

        fun getDatabase(context: Context): PasswordDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PasswordDatabase::class.java,
                    "ZeroKey_Database"
                )
                .addMigrations(*MIGRATIONS)
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
