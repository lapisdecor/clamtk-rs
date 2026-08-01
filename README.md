![preview](clamtk-rs.png "Clamtk-rs")

# **Build & Run Instructions**  
You have several choices.
  
## Prerequisites
If you want to build from source you will need:  
 - Rust toolchain (rustup.rs)  
 - GTK4 development libraries  
 - ClamAV installed (clamscan, freshclam)  
   
## How to Install GTK4 dev libraries (Ubuntu/Debian)  
sudo apt install libgtk-4-dev libadwaita-1-dev  
   
## How to Install GTK4 dev libraries (Fedora)  
sudo dnf install gtk4-devel libadwaita-devel  
   
## If building from source Install ClamAV  
sudo apt install clamav clamav-daemon # Debian/Ubuntu  
sudo dnf install clamav clamd # Fedora  
   
## Build  
cd clamtk-rs  
cargo build --release  
   
## Run  
cargo run --release  
   
## Or install system-wide  
sudo cargo install --path .  
  
## If you want to Build a snap  
sudo snap install snapcraft  
cd clamtk-rs  
snapcraft pack 
  
## Install the built snap  
sudo snap install --dangerous clamtk-rs_1.0.0_amd64.snap

# Is there a snap in the Ubuntu store?
Not yet. I hope it will be there soon.  
 
