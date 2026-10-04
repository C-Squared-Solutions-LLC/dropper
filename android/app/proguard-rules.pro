# Dropper uses no reflection-based serialization; org.json is part of the platform.
# Strip verbose/debug/info logging from release builds.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
