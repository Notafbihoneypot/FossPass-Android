# FossPass R8/Proguard rules
# Standard Android optimizations
-optimizationpasses 5
-allowaccessmodification
-dontpreverify

# Keep UniFFI/JNI related stuff (for future Rust integration)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Add more rules here as Rust/UniFFI is added
