package com.hariharan.zerokey.data.database

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
        SyncMetadataEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun passwordDao(): PasswordDao

    companion object {

        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {

                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "zerokey_database"
                ).build()

                INSTANCE = instance
                instance
            }
        }
    }
}
