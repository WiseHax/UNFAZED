fn main() {
    println!("== UNFAZED Rust Init Tool ==");
    println!("Performing basic system checks...");

    // OS Check
    if cfg!(target_os = "windows") {
        println!("[✓] OS: Windows");
    } else {
        println!("[!] Not running on Windows.");
    }

    // Architecture Check
    if cfg!(target_arch = "x86_64") {
        println!("[✓] Architecture: 64-bit");
    } else {
        println!("[!] Not 64-bit architecture");
    }

    // Final
    println!("[✓] Initialization complete.");
}
