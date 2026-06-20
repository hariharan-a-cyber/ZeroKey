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
    fun provideBiometricVaultUnlockManager(@ApplicationContext context: Context):
        com.hariharan.zerokey.security.BiometricVaultUnlockManager =
        com.hariharan.zerokey.security.BiometricVaultUnlockManager(context)

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
        masterPasswordManager,
        encryptionManager,
        database.vaultMetadataDao()
    )

    @Provides
    @Singleton
    fun provideAuditLogManager(
        database: PasswordDatabase,
        masterPasswordManager: MasterPasswordManager,
        encryptionManager: EncryptionManager
    ): AuditLogManager = AuditLogManager(database.auditLogDao(), masterPasswordManager, encryptionManager)

    @Provides
    @Singleton
    fun provideFirebaseFirestore(): FirebaseFirestore = FirebaseFirestore.getInstance()

    @Provides
    @Singleton
    fun provideDeviceTrustManager(@ApplicationContext context: Context, firestore: FirebaseFirestore): DeviceTrustManager = DeviceTrustManager(context, firestore)

    @Provides
    @Singleton
    fun provideCryptoEngine(): CryptoEngine = CryptoEngine()

    @Provides
    @Singleton
    fun provideDeviceSyncManager(
        firestore: FirebaseFirestore,
        hmacEngine: HmacEngine,
        cryptoEngine: CryptoEngine,
        deviceTrustManager: DeviceTrustManager
    ): DeviceSyncManager = DeviceSyncManager(
        firestore, 
        cryptoEngine, 
        hmacEngine, 
        VaultConflictResolver(cryptoEngine, hmacEngine), 
        deviceTrustManager
    )

    @Provides
    @Singleton
    fun provideCredentialShareManager(
        @ApplicationContext context: Context,
        firestore: FirebaseFirestore
    ): CredentialShareManager = CredentialShareManager(context, firestore)

    @Provides
    @Singleton
    fun providePrivacyModeManager(@ApplicationContext context: Context): PrivacyModeManager = PrivacyModeManager(context)

    @Provides
    @Singleton
    fun provideBillingManager(@ApplicationContext context: Context): com.hariharan.zerokey.security.BillingManager = com.hariharan.zerokey.security.BillingManager(context)

    @Provides
    @Singleton
    fun provideFeatureAccessManager(billingManager: com.hariharan.zerokey.security.BillingManager): com.hariharan.zerokey.security.FeatureAccessManager {
        return com.hariharan.zerokey.security.FeatureAccessManager(billingManager.isPremium)
    }

    @Provides
    @Singleton
    fun provideVaultSerializer(encryptionManager: EncryptionManager): VaultSerializer = VaultSerializer(encryptionManager)

    @Provides
    @Singleton
    fun provideVaultBackupManager(
        repository: PasswordRepository,
        serializer: VaultSerializer
    ): VaultBackupManager = VaultBackupManager(repository, serializer)

    @Provides
    @Singleton
    fun provideFirebaseAuthenticator(): com.hariharan.zerokey.security.FirebaseAuthenticator = 
        com.hariharan.zerokey.security.FirebaseAuthenticator()
}
