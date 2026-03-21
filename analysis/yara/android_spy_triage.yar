/*
  Android APK triage: remote commands + illegal geo tracking + eavesdropping (mic) +
  traffic interception + screen/camera surveillance.

  Usage:
    yara -r android_spy_triage.yar <apktool_dir> <jadx_dir> app.apk

  Notes:
    - YARA matches static indicators (strings/classes/manifest attrs), not behavior.
    - These rules are high-recall. Expect false positives on legitimate apps (maps, messengers, VPN, screen recorders).
    - For implant/backdoor detection you usually want combinations (permission + API + persistence/remote channel).
*/

rule ANDROID_Remote_Command_MQTT_WS
{
  meta:
    category = "remote_command"
    confidence = "medium"
    description = "MQTT/WebSocket client markers + command-like vocabulary"
  strings:
    // protocols / libs
    $mqtt1 = "org.eclipse.paho.client.mqttv3" ascii
    $mqtt2 = "MqttAndroidClient" ascii
    $mqtt3 = "connectComplete" ascii
    $mqtt4 = "subscribe(" ascii
    $mqtt5 = "publish(" ascii
    $ws1   = "okhttp3.WebSocket" ascii
    $ws2   = "newWebSocket" ascii
    $ws3   = "onMessage(" ascii
    $ws4   = "wss://" ascii
    $ws5   = "ws://" ascii

    // command-ish keys (generic, tune per target)
    $cmd1  = /\"(cmd|command|exec|shell|task|opcode|action|payload)\"\s*:/ nocase ascii
    $cmd2  = /(cmd|command|exec|shell|task|opcode)\b/ nocase ascii
  condition:
    (1 of ($mqtt*) or 2 of ($ws*)) and (1 of ($cmd*) )
}

rule ANDROID_Remote_Command_FCM
{
  meta:
    category = "remote_command"
    confidence = "medium"
    description = "Firebase Cloud Messaging handler + command-ish keys"
  strings:
    $fcm1 = "com.google.firebase.messaging.FirebaseMessagingService" ascii
    $fcm2 = "onMessageReceived" ascii
    $fcm3 = "com.google.firebase.MESSAGING_EVENT" ascii
    $fcm4 = "RemoteMessage" ascii

    $cmd1 = /\"(cmd|command|task|action|opcode|payload)\"\s*:/ nocase ascii
    $cmd2 = /(cmd|command|exec|shell|task|opcode)\b/ nocase ascii
  condition:
    2 of ($fcm*) and (1 of ($cmd*))
}

rule ANDROID_Geo_Tracking_Location_APIs
{
  meta:
    category = "geo_tracking"
    confidence = "medium"
    description = "Location permissions + LocationManager/FusedLocationProvider usage"
  strings:
    // permissions / manifest attrs
    $p1 = "android.permission.ACCESS_FINE_LOCATION" ascii
    $p2 = "android.permission.ACCESS_COARSE_LOCATION" ascii
    $p3 = "android.permission.ACCESS_BACKGROUND_LOCATION" ascii
    $p4 = "foregroundServiceType=\"location\"" ascii

    // APIs
    $lm1 = "android.location.LocationManager" ascii
    $lm2 = "requestLocationUpdates" ascii
    $lm3 = "getLastKnownLocation" ascii
    $gl1 = "com.google.android.gms.location.FusedLocationProviderClient" ascii
    $gl2 = "requestLocationUpdates" ascii
    $gl3 = "getLastLocation" ascii
  condition:
    ( (any of ($p1,$p2,$p3,$p4)) and (1 of ($lm*) or 1 of ($gl*)) )
}

rule ANDROID_Geo_Tracking_Persistence
{
  meta:
    category = "geo_tracking"
    confidence = "low"
    description = "Location + persistence scheduling indicators (WorkManager/Job/Alarm/Boot)"
  strings:
    $boot = "android.intent.action.BOOT_COMPLETED" ascii
    $wm   = "androidx.work.WorkManager" ascii
    $job  = "JobScheduler" ascii
    $al1  = "AlarmManager" ascii

    $p1 = "android.permission.ACCESS_FINE_LOCATION" ascii
    $p2 = "android.permission.ACCESS_BACKGROUND_LOCATION" ascii
    $loc = "requestLocationUpdates" ascii
  condition:
    (any of ($p1,$p2) or $loc) and (1 of ($boot,$wm,$job,$al1))
}

rule ANDROID_Eavesdropping_Microphone
{
  meta:
    category = "eavesdropping"
    confidence = "medium"
    description = "RECORD_AUDIO + AudioRecord/MediaRecorder usage"
  strings:
    $perm = "android.permission.RECORD_AUDIO" ascii

    $ar1 = "android.media.AudioRecord" ascii
    $ar2 = "startRecording" ascii
    $mr1 = "android.media.MediaRecorder" ascii
    $mr2 = "setAudioSource" ascii
    $mr3 = "AudioSource.MIC" ascii
    $mr4 = "AudioSource.VOICE_CALL" ascii
    $mr5 = "AudioSource.VOICE_COMMUNICATION" ascii
  condition:
    $perm and ( ( $ar1 and $ar2 ) or ( $mr1 and ( $mr2 or $mr3 or $mr4 or $mr5 ) ) )
}

rule ANDROID_Camera_Surveillance
{
  meta:
    category = "camera"
    confidence = "medium"
    description = "CAMERA permission + camera APIs (camera2/legacy) indicators"
  strings:
    $perm1 = "android.permission.CAMERA" ascii
    $perm2 = "foregroundServiceType=\"camera\"" ascii

    $c2_1 = "android.hardware.camera2.CameraManager" ascii
    $c2_2 = "android.hardware.camera2.CameraDevice" ascii
    $c2_3 = "CameraCaptureSession" ascii
    $c2_4 = "createCaptureSession" ascii

    $c1_1 = "android.hardware.Camera" ascii
    $c1_2 = "startPreview" ascii
    $c1_3 = "takePicture" ascii
  condition:
    (any of ($perm1,$perm2)) and (2 of ($c2*) or 2 of ($c1*))
}

rule ANDROID_Screen_Capture_MediaProjection
{
  meta:
    category = "screen"
    confidence = "high"
    description = "MediaProjection-based screen capture indicators"
  strings:
    $mp1 = "android.media.projection.MediaProjectionManager" ascii
    $mp2 = "createScreenCaptureIntent" ascii
    $mp3 = "android.media.projection.MediaProjection" ascii
    $vd1 = "createVirtualDisplay" ascii
    $ir1 = "android.media.ImageReader" ascii
    $fst = "foregroundServiceType=\"mediaProjection\"" ascii
  condition:
    2 of ($mp*) and ( $vd1 or $ir1 or $fst )
}

rule ANDROID_Accessibility_Screen_Observation
{
  meta:
    category = "screen"
    confidence = "medium"
    description = "AccessibilityService usage (can observe UI, sometimes screenshots)"
  strings:
    $b1 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii
    $a1 = "android.accessibilityservice.AccessibilityService" ascii
    $a2 = "getRootInActiveWindow" ascii
    $a3 = "AccessibilityEvent" ascii
    $a4 = "TYPE_VIEW_TEXT_CHANGED" ascii
    $a5 = "TYPE_WINDOW_CONTENT_CHANGED" ascii
    $a6 = "takeScreenshot" ascii
  condition:
    ($b1 or $a1) and (2 of ($a2,$a3,$a4,$a5,$a6))
}

rule ANDROID_Traffic_Interception_VPN_TUN
{
  meta:
    category = "traffic_intercept"
    confidence = "high"
    description = "VpnService/TUN-based traffic interception indicators"
  strings:
    $v1 = "android.net.VpnService" ascii
    $v2 = "VpnService$Builder" ascii
    $v3 = "establish(" ascii
    $v4 = "addRoute" ascii
    $v5 = "addAddress" ascii
    $v6 = "setSession" ascii

    $tun1 = "tun" nocase ascii
    $tun2 = "TUN" ascii
    $pcap1 = "pcap" nocase ascii
    $pcap2 = "tcpdump" nocase ascii
  condition:
    ($v1 or $v2) and $v3 and ($v4 or $v5 or $v6) and (any of ($tun*) or any of ($pcap*))
}

rule ANDROID_TLS_TrustAll_or_MITM_Indicators
{
  meta:
    category = "traffic_intercept"
    confidence = "high"
    description = "Trust-all TLS patterns (MITM-enabling) + HTTP client markers"
  strings:
    $tm1  = "javax.net.ssl.X509TrustManager" ascii
    $tm2  = "checkServerTrusted" ascii
    $hnv1 = "javax.net.ssl.HostnameVerifier" ascii
    $ssl1 = "SSLContext" ascii
    $ok1  = "okhttp3.OkHttpClient" ascii
    $ret  = "return true" ascii

    // optional: explicit MITM tool names (rare in prod apps, but shows in test backdoors)
    $mitm1 = "burp" nocase ascii
    $mitm2 = "mitmproxy" nocase ascii
    $mitm3 = "charles" nocase ascii
  condition:
    (
        ( ($tm1 and $tm2 and $ssl1) or ($hnv1 and $ret) ) and ($ok1 or $ssl1)
    ) or (
        any of ($mitm*) and ($ok1 or $ssl1 or $tm1 or $hnv1)
    )
}

rule ANDROID_Combined_Spy_Profile_Strong
{
  meta:
    category = "combined"
    confidence = "high"
    description = "Strong combo: remote command channel + (geo or mic or camera or screen) + persistence or trust-all"
  strings:
    // remote channels
    $fcm = "FirebaseMessagingService" ascii
    $ws  = "okhttp3.WebSocket" ascii
    $mqtt= "mqtt" nocase ascii

    // capabilities
    $geo1 = "ACCESS_FINE_LOCATION" ascii
    $geo2 = "FusedLocationProviderClient" ascii
    $mic  = "android.permission.RECORD_AUDIO" ascii
    $cam  = "android.permission.CAMERA" ascii
    $scr1 = "MediaProjectionManager" ascii
    $acc  = "BIND_ACCESSIBILITY_SERVICE" ascii

    // persistence / TLS bypass
    $boot = "BOOT_COMPLETED" ascii
    $wm   = "WorkManager" ascii
    $job  = "JobScheduler" ascii
    $trust= "X509TrustManager" ascii
  condition:
    (any of ($fcm,$ws,$mqtt)) and
    (any of ($geo1,$geo2,$mic,$cam,$scr1,$acc)) and
    (any of ($boot,$wm,$job,$trust))
}

rule ANDROID_Device_Admin_Abuse
{
  meta:
    category = "device_admin"
    confidence = "medium"
    description = "Device admin API usage indicators"
  strings:
    $da1 = "DevicePolicyManager" ascii
    $da2 = "BIND_DEVICE_ADMIN" ascii
    $da3 = "DeviceAdminReceiver" ascii
    $da4 = "lockNow" ascii
    $da5 = "wipeData" ascii
    $da6 = "resetPassword" ascii
  condition:
    2 of ($da*)
}

rule ANDROID_Anti_Tamper_Signature_Check
{
  meta:
    category = "anti_tamper"
    confidence = "low"
    description = "Signature verification with kill/exit on mismatch"
  strings:
    $sig1 = "PackageInfo" ascii
    $sig2 = "signatures" ascii
    $sig3 = "hashCode" ascii
    $kill1 = "Process.killProcess" ascii
    $kill2 = "System.exit" ascii
  condition:
    2 of ($sig*) and 1 of ($kill1, $kill2)
}
