package com.osmapp.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            // TODO: Wire up BleTransport + CompanionAppUI
            androidx.compose.material3.Text("OSM Companion — Android (BLE transport coming soon)")
        }
    }
}
