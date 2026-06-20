package com.hariharan.zerokey.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        PasswordEntity::class,
        VaultMetadata::class,
        AuditLogEntity::class,
        PasskeyEntity::class,
        SecurityEventEntity::class,
        SharedCredentialEntity::class,
        SyncMetadataEntity::class,
        SecurityScoreHistoryEntity::class
    ],
    version = 7,
    exportSchema = false
)
abstract class PasswordDatabase : RoomDatabase() {
    abstract fun passwordDao(): PasswordDao
    abstract fun vaultMetadataDao(): VaultMetadataDao
    abstract fun auditLogDao(): AuditLogDao

    companion object {

        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE passwords ADD COLUMN isDeleted INTEGER NOT NULL DEFAULT 0")
            }
        }

        private val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE passwords ADD COLUMN lastModified INTEGER NOT NULL DEFAULT 0")
                db.execSQL("UPDATE passwords SET lastModified = createdAt WHERE lastModified = 0")
            }
        }

        private val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS passkey_records (
                        credentialId TEXT NOT NULL PRIMARY KEY,
                        domain TEXT NOT NULL,
                        userId TEXT NOT NULL,
                        username TEXT NOT NULL,
                        publicKey TEXT NOT NULL,
                        createdAt INTEGER NOT NULL,
                        lastUsedAt INTEGER,
                        syncId TEXT
                    )
                """.trimIndent())
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS security_events (
                        id TEXT NOT NULL PRIMARY KEY,
                        eventType TEXT NOT NULL,
                        domain TEXT,
                        packageName TEXT,
                        reason TEXT,
                        severity TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        resolved INTEGER NOT NULL DEFAULT 0
                    )
                """.trimIndent())
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        eventType TEXT NOT NULL,
                        details TEXT NOT NULL,
                        timestamp INTEGER NOT NULL
                    )
                """.trimIndent())
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS vault_metadata (
                        id INTEGER NOT NULL PRIMARY KEY,
                        vaultVersion INTEGER NOT NULL DEFAULT 1,
                        lastSyncTimestamp INTEGER NOT NULL DEFAULT 0,
                        deviceId TEXT NOT NULL DEFAULT 'local',
                        vaultEpochId TEXT NOT NULL DEFAULT '',
                        lastKnownHmac TEXT
                    )
                """.trimIndent())
            }
        }

        private val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS incoming_shares (
                        id TEXT NOT NULL PRIMARY KEY,
                        senderUserId TEXT NOT NULL,
                        encryptedPayload TEXT NOT NULL,
                        ephemeralSenderPublicKey TEXT NOT NULL,
                        receivedAt INTEGER NOT NULL,
                        expiresAt INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        decryptedCredentialId INTEGER
                    )
                """.trimIndent())
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS vault_sync_metadata (
                        userId TEXT NOT NULL PRIMARY KEY,
                        deviceId TEXT NOT NULL,
                        lastPushedAt INTEGER,
                        lastPulledAt INTEGER,
                        localVersion INTEGER NOT NULL DEFAULT 0,
                        remoteVersion INTEGER,
                        syncStatus TEXT NOT NULL DEFAULT 'IDLE',
                        privacyMode INTEGER NOT NULL DEFAULT 0
                    )
                """.trimIndent())
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS security_score_history (
                        id TEXT NOT NULL PRIMARY KEY,
                        userId TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        grade TEXT NOT NULL,
                        weakCount INTEGER NOT NULL DEFAULT 0,
                        duplicateCount INTEGER NOT NULL DEFAULT 0,
                        breachCount INTEGER NOT NULL DEFAULT 0,
                        recordedAt INTEGER NOT NULL
                    )
                """.trimIndent())
            }
        }

        private val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE passwords ADD COLUMN passkeyCredentialId TEXT")
                db.execSQL("ALTER TABLE passwords ADD COLUMN lastBreachCheck INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE passwords ADD COLUMN breachFound INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE passwords ADD COLUMN recordUid TEXT")
                db.execSQL("ALTER TABLE passwords ADD COLUMN encryptionVersion INTEGER NOT NULL DEFAULT 1")
                db.execSQL("ALTER TABLE passwords ADD COLUMN schemaVersion INTEGER NOT NULL DEFAULT 1")
                // Backfill recordUid for rows that don't have one yet (legacy data).
                db.execSQL("UPDATE passwords SET recordUid = lower(hex(randomblob(16))) WHERE recordUid IS NULL")
            }
        }

        // Phase 9 removes Emergency Access — drop the old table if it exists.
        private val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("DROP TABLE IF EXISTS emergency_access_config")
            }
        }

        private val MIGRATIONS: Array<Migration> = arrayOf(
            MIGRATION_1_2,
            MIGRATION_2_3,
            MIGRATION_3_4,
            MIGRATION_4_5,
            MIGRATION_5_6,
            MIGRATION_6_7
        )

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
