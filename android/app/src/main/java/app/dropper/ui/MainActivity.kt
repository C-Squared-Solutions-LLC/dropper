package app.dropper.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.dropper.AppGraph
import app.dropper.DropperApp
import app.dropper.net.PairingUi
import app.dropper.service.ConnectionService

class MainActivity : ComponentActivity() {
    private lateinit var graph: AppGraph

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        graph = DropperApp.graph(this)
        setContent {
            DropperTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    Root(graph)
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        graph.visibility.onStart()
        graph.resume() // opening the app after Quit brings the connection back
        ConnectionService.start(this)
    }

    override fun onStop() {
        graph.visibility.onStop()
        super.onStop()
    }
}

private enum class Screen { HOME, SETTINGS }

@Composable
private fun Root(graph: AppGraph) {
    val pairing by graph.pairingRepo.state.collectAsStateWithLifecycle()
    val pairingUi by graph.pairing.state.collectAsStateWithLifecycle()
    var screen by rememberSaveable { mutableStateOf(Screen.HOME) }

    when {
        pairing == null || pairingUi != PairingUi.Idle -> PairingScreen(graph)
        screen == Screen.SETTINGS -> {
            BackHandler { screen = Screen.HOME }
            SettingsScreen(graph, onBack = { screen = Screen.HOME })
        }
        else -> HomeScreen(graph, onOpenSettings = { screen = Screen.SETTINGS })
    }
}
