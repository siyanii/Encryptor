# 🔒 Secure File Encryptor/Decryptor 🛡️

| Section | Content |
|---------|---------|
| **🌟 Description** | A secure GUI tool for file encryption/decryption using military-grade AES-GCM encryption |
| **✨ Features** | |
| 🔐 Encryption | AES-GCM 256-bit encryption (NSA-approved) |
| 🔓 Decryption | Authenticated decryption with tamper detection |
| 📁 Large Files | Supports huge files up to 10GB (chunked processing) |
| 🖥️ GUI | Beautiful PyQt5 interface with dark theme |
| 🔑 Security | PBKDF2-HMAC-SHA256 with 600,000 iterations |
| **📦 Requirements** | |
| 🐍 Python Version | 3.6+ (Recommended: 3.8+) |
| 💻 System | Windows/macOS/Linux |
| 📚 Dependencies | `PyQt5`, `cryptography`, `qt_material` |
| ⚙️ Install Command | `pip install PyQt5 cryptography qt_material` |
| **📋 Usage Guide** | |
| 🔒 Encryption | 1. Click "Select File"<br>2. Set output path (.encrypted)<br>3. Enter password + confirmation<br>4. Click "Start Encryption"<br>5. Wait for completion ✅ |
| 🔓 Decryption | 1. Click "Select Encrypted File"<br>2. Set output path<br>3. Enter original password<br>4. Click "Start Decryption"<br>5. Get your original file back ✅ |
| ⚠️ Important | - Never lose your password!<br>- Keep backups of important files<br>- Cancel operations using window close |
| **⚙️ Technical Specs** | |
| 🛠️ Algorithm | AES-GCM (Authenticated Encryption) |
| 🔑 Key Size | 256-bit (Military Grade) |
| 🔄 Iterations | 600,000 (NIST Recommended) |
| 🧩 Chunk Size | 1MB (Optimal Performance) |
| 🧂 Salt Size | 16 bytes |
| 🔢 Nonce Size | 12 bytes |
| **🔐 Security Notes** | - 🔄 Cryptographically secure RNG<br>- ✅ Automatic integrity verification<br>- 🧹 Cleanup on failure<br>- 🛡️ Protection against common attacks |
| **📜 License** | MIT License - Free for everyone |
| **📸 Preview** | ![App Screenshot](https://github.com/logand166/Encryptor/blob/main/Screenshot.jpg?raw=true) |
| **☕ Support** | [Buy Me a Coffee](https://www.buymeacoffee.com/logand) <a href="https://www.buymeacoffee.com/logand"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=logand&button_colour=40DCA5&font_colour=ffffff&font_family=Cookie&outline_colour=000000&coffee_colour=FFDD00" height="25"/></a> |
