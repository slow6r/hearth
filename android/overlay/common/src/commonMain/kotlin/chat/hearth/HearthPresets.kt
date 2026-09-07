package chat.hearth

/**
 * Hearth network defaults — the single place where "which servers does this app talk to"
 * is decided (ТЗ §8.2 п.1–5).
 *
 * Upstream ships a list of SimpleX operators and their relays. In this fork that list is
 * empty and the operator screen is hidden: the app must be incapable of reaching the
 * public network, not merely configured not to (ТЗ §1.2).
 *
 * INTEGRATION POINTS (see ../../../../../patches/0001-presets.md):
 *   - upstream preset list  -> return [presetServers] (empty until a bundle is imported)
 *   - upstream ICE defaults -> [defaultIceServers]
 *   - upstream operator UI  -> hidden, see patches/0002-hide-operators.md
 */
object HearthPresets {

  /**
   * Servers shipped in the APK: none.
   *
   * The relay address contains a password (ТЗ §6.2), so it cannot be baked into a
   * binary that is passed around on a USB stick — it arrives with the bundle QR and
   * lives in the app's encrypted storage from then on.
   */
  val presetServers: List<String> = emptyList()

  /** Public operator presets are off, permanently. */
  const val PRESETS_ENABLED = false

  /** ТЗ §8.2 п.5: private message routing is on by default and not weakened. */
  const val PRIVATE_ROUTING_DEFAULT = "always"

  /**
   * Delivery is a foreground service holding a persistent connection to our relay.
   * There is no notification server in the contour, so Periodic/Push are not offered.
   */
  const val NOTIFICATION_MODE = "instant"

  /** ТЗ §8.2 п.6: disappearing messages default for new contacts. */
  const val DEFAULT_DISAPPEARING_MESSAGES_SECONDS = 7 * 24 * 60 * 60

  /**
   * ICE servers currently configured on this device.
   *
   * Empty until a bundle is imported. Upstream's fallback to public STUN must be
   * removed rather than left as a fallback: an empty ICE list means calls fail loudly,
   * which is the correct outcome — a call that succeeds via `stun.l.google.com` has
   * already leaked the participant's address (ТЗ §6.4).
   */
  fun defaultIceServers(applied: HearthBundle?): List<String> =
    applied?.ice ?: emptyList()

  /**
   * Servers to hand to the SimpleX core after a bundle import.
   *
   * Returns them in upstream's own `smp://` / `xftp://` string form: this fork never
   * touches the address format or the parser (ТЗ §8.3).
   */
  fun serversFrom(bundle: HearthBundle): HearthServers = HearthServers(
    smp = bundle.smp,
    xftp = bundle.xftp,
    ice = bundle.ice,
  )
}

/** The set of servers this device uses. Nothing else is reachable. */
data class HearthServers(
  val smp: List<String>,
  val xftp: List<String>,
  val ice: List<String>,
)
