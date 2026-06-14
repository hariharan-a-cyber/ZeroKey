package com.hariharan.zerokey.di

import android.content.Context
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.crypto.HmacEngine
import com.hariharan.zerokey.core.crypto.KeyDerivationManager
import com.hariharan.zerokey.core.database.PasswordDatabase
import com.hariharan.zerokey.core.security.AuthAttemptManager
import com.hariharan.zerokey.core.security.BreachMonitor
import com.hariharan.zerokey.core.security.MasterPasswordManager
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.security.AuditLogManager
import com.hariharan.zerokey.security.DeviceTrustManager
import com.hariharan.zerokey.sharing.CredentialShareManager
import com.hariharan.zerokey.sync.DeviceSyncManager
import com.hariharan.zerokey.sync.VaultConflictResolver
import com.hariharan.zerokey.core.crypto.CryptoEngine
import com.google.firebase.firestore.FirebaseFirestore
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

import com.hariharan.zerokey.security.PrivacyModeManager
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.data.sync.VaultSerializer
import com.hariharan.zerokey.emergency.EmergencyNotificationService
import com.hariharan.zerokey.emergency.EmergencyAccessManager

@Module
@InstallIn(SingletonComponent::class)
object SecurityModule {

    @Provides
    @Singleton
    fun provideEncryptionManager(): EncryptionManager = EncryptionManager()

    @Provides
    @Singleton
    fun provideKeyDerivationManager(): KeyDerivationManager = KeyDerivationManager()

    @Provides
    @Singleton
    fun provideMasterPasswordManager(
        encryptionManager: EncryptionManager,
        keyDerivationManager: KeyDerivationManager
    ): MasterPasswordManager {
        return MasterPasswordManager(encryptionManager, keyDerivationManager)
    }

    @Provides
    @Singleton
    fun provideBreachMonitor(): BreachMonitor = BreachMonitor()

    @Provides
    @Singleton
    fun provideHmacEngine(): HmacEngine = HmacEngine()

    @Provides
    @Singleton
    fun provideAuthAttemptManager(@ApplicationContext context: Context): AuthAttemptManager = AuthAttemptManager(context)

    @Provides
    @Singleton
    fun providePasswordDatabase(@ApplicationContext context: Context): PasswordDatabase = PasswordDatabase.getDatabase(context)

    @Provides
    @Singleton
    fun providePasswordRepository(
        database: PasswordDatabase,
        masterPasswordManager: MasterPasswordManager,
        encryptionManager: EncryptionManager
    ): PasswordRepository = PasswordRepository(
        database.passwordDao(), 
        database.vaultMetadataDao(),
        masterPasswordManager,
        encryptionManager
    )

    @Provides
    @Singleton
    fun provideAuditLogManager(database: PasswordDatabase): AuditLogManager = AuditLogManager(database.auditLogDao())

    @Provides
    @Singleton
    fun provideFirebaseFirestore(): FirebaseFirestore = FirebaseFirestore.getInstance()

    @Provides
    @Singleton
    fun provideDeviceTrustManager(@ApplicationContext context: Context, firestore: FirebaseFirestore): DeviceTrustManager = DeviceTrustManager(context, firestore)

    @Provides
    @Singleton
    fun provideDeviceSyncManager(
        firestore: FirebaseFirestore,
        hmacEngine: HmacEngine,
        deviceTrustManager: DeviceTrustManager
    ): DeviceSyncManager = DeviceSyncManager(
        firestore, 
        CryptoEngine(), 
        hmacEngine, 
        VaultConflictResolver(CryptoEngine(), hmacEngine), 
        deviceTrustManager
    )

    @Provides
    @Singleton
    fun provideCredentialShareManager(firestore: FirebaseFirestore, hmacEngine: HmacEngine): CredentialShareManager = CredentialShareManager(firestore, hmacEngine)

    @Provides
    @Singleton
    fun providePrivacyModeManager(@ApplicationContext context: Context): PrivacyModeManager = PrivacyModeManager(context)

    @Provides
    @Singleton
    fun provideVaultSerializer(): VaultSerializer = VaultSerializer()

    @Provides
    @Singleton
    fun provideVaultBackupManager(
        repository: PasswordRepository,
        serializer: VaultSerializer
    ): VaultBackupManager = VaultBackupManager(repository, serializer)

    @Provides
    @Singleton
    fun provideEmergencyAccessManager(
        firestore: FirebaseFirestore
    ): EmergencyAccessManager = EmergencyAccessManager(
        firestore,
        CryptoEngine(),
        object : EmergencyNotificationService {
            override suspend fun notifyOwnerOfRequest(ownerId: String, contactEmail: String, cancelDeadline: Long) {}
            override suspend fun notifyRequestCancelled(contactEmail: String) {}
            override suspend fun notifyAccessGranted(ownerId: String, contactEmail: String) {}
        }
    )
}
