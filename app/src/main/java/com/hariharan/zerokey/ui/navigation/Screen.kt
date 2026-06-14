package com.hariharan.zerokey.ui.navigation

sealed class Screen(val route: String) {
    object Vault : Screen("vault")
    object AddPassword : Screen("add_password")
    object PasswordDetail : Screen("password_detail/{id}") { 
        fun createRoute(id: Int) = "password_detail/$id" 
    }
    object SecurityDashboard : Screen("security_dashboard")
    object PasswordHealth : Screen("password_health")
    object SecurityActivity : Screen("security_activity")
    object CredentialSharing : Screen("credential_sharing")
    object CloudSync : Screen("cloud_sync")
    object Settings : Screen("settings")
    object Generator : Screen("generator")
    object DeviceManagement : Screen("device_management")
}
